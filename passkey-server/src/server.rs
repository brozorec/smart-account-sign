//! HTTP server for WebAuthn operations

use crate::html;
use crate::{PasskeyAssertion, PasskeyCredential};
use anyhow::Result;
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;
use tower_http::cors::CorsLayer;

const SERVER_PORT: u16 = 3000;

/// Start server for signing operation
pub async fn start_sign_server(
    challenge: &[u8],
    credential_id: &[u8],
    rp_id: &str,
) -> Result<PasskeyAssertion> {
    let challenge_hex = hex::encode(challenge);
    let credential_id_hex = hex::encode(credential_id);
    let rp_id = rp_id.to_string();

    let (tx, rx) = oneshot::channel();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

    let app_state = SignServerState {
        challenge: challenge_hex.clone(),
        credential_id: credential_id_hex.clone(),
        rp_id: rp_id.clone(),
        result_sender: tx,
    };

    let app = Router::new()
        .route("/", get(sign_page_handler))
        .route("/callback", post(sign_callback_handler))
        .route("/success", get(success_handler))
        .layer(CorsLayer::permissive())
        .with_state(Arc::new(app_state));

    let addr = SocketAddr::from(([127, 0, 0, 1], SERVER_PORT));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    eprintln!("🌐 Starting passkey server at http://localhost:{}", SERVER_PORT);
    eprintln!("📱 Opening browser...");

    // Open browser
    let url = format!("http://localhost:{}", SERVER_PORT);
    if let Err(e) = webbrowser::open(&url) {
        eprintln!("⚠️  Failed to open browser automatically: {}", e);
        eprintln!("   Please open this URL manually: {}", url);
    }

    // Spawn server
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Wait for result or timeout
    let result = tokio::time::timeout(std::time::Duration::from_secs(300), rx).await??;

    // Shutdown server
    server_handle.abort();

    Ok(result)
}

/// Start server for registration operation
pub async fn start_register_server(
    user_id: &str,
    user_name: &str,
    rp_id: &str,
) -> Result<PasskeyCredential> {
    let user_id = user_id.to_string();
    let user_name = user_name.to_string();
    let rp_id = rp_id.to_string();

    let (tx, rx) = oneshot::channel();
    let tx = Arc::new(tokio::sync::Mutex::new(Some(tx)));

    let app_state = RegisterServerState {
        user_id: user_id.clone(),
        user_name: user_name.clone(),
        rp_id: rp_id.clone(),
        result_sender: tx,
    };

    let app = Router::new()
        .route("/register", get(register_page_handler))
        .route("/register/callback", post(register_callback_handler))
        .route("/success", get(success_handler))
        .layer(CorsLayer::permissive())
        .with_state(Arc::new(app_state));

    let addr = SocketAddr::from(([127, 0, 0, 1], SERVER_PORT));
    let listener = tokio::net::TcpListener::bind(addr).await?;

    eprintln!("🌐 Starting passkey server at http://localhost:{}", SERVER_PORT);
    eprintln!("📱 Opening browser...");

    // Open browser
    let url = format!("http://localhost:{}/register", SERVER_PORT);
    if let Err(e) = webbrowser::open(&url) {
        eprintln!("⚠️  Failed to open browser automatically: {}", e);
        eprintln!("   Please open this URL manually: {}", url);
    }

    // Spawn server
    let server_handle = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // Wait for result or timeout
    let result = tokio::time::timeout(std::time::Duration::from_secs(300), rx).await??;

    // Shutdown server
    server_handle.abort();

    Ok(result)
}

// Sign server state and handlers

#[derive(Clone)]
struct SignServerState {
    challenge: String,
    credential_id: String,
    rp_id: String,
    result_sender: Arc<tokio::sync::Mutex<Option<oneshot::Sender<PasskeyAssertion>>>>,
}

async fn sign_page_handler(State(state): State<Arc<SignServerState>>) -> Html<String> {
    Html(html::sign_page(
        &state.challenge,
        &state.credential_id,
        &state.rp_id,
    ))
}

#[derive(Debug, Deserialize)]
struct SignCallbackPayload {
    signature: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "credentialId")]
    credential_id: String,
}

async fn sign_callback_handler(
    State(state): State<Arc<SignServerState>>,
    Json(payload): Json<SignCallbackPayload>,
) -> impl IntoResponse {
    let assertion = PasskeyAssertion {
        signature: payload.signature,
        authenticator_data: payload.authenticator_data,
        client_data_json: payload.client_data_json,
        credential_id: payload.credential_id,
    };

    if let Some(tx) = state.result_sender.lock().await.take() {
        let _ = tx.send(assertion);
    }

    StatusCode::OK
}

// Register server state and handlers

#[derive(Clone)]
struct RegisterServerState {
    user_id: String,
    user_name: String,
    rp_id: String,
    result_sender: Arc<tokio::sync::Mutex<Option<oneshot::Sender<PasskeyCredential>>>>,
}

async fn register_page_handler(State(state): State<Arc<RegisterServerState>>) -> Html<String> {
    Html(html::register_page(
        &state.user_id,
        &state.user_name,
        &state.rp_id,
    ))
}

#[derive(Debug, Deserialize)]
struct RegisterCallbackPayload {
    #[serde(rename = "credentialId")]
    credential_id: String,
    #[serde(rename = "attestationObject")]
    #[allow(dead_code)]
    attestation_object: String,
    #[serde(rename = "clientDataJSON")]
    #[allow(dead_code)]
    client_data_json: String,
}

async fn register_callback_handler(
    State(state): State<Arc<RegisterServerState>>,
    Json(payload): Json<RegisterCallbackPayload>,
) -> impl IntoResponse {
    // Parse attestation object to extract public key
    let public_key = match extract_public_key_from_attestation(&payload.attestation_object) {
        Ok(pk) => pk,
        Err(e) => {
            eprintln!("Failed to extract public key: {}", e);
            return StatusCode::INTERNAL_SERVER_ERROR;
        }
    };

    let credential = PasskeyCredential {
        credential_id: payload.credential_id.clone(),
        public_key,
        public_key_algorithm: -7, // ES256
        rp_id: state.rp_id.clone(),
        user_id: state.user_id.clone(),
        user_name: state.user_name.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    if let Some(tx) = state.result_sender.lock().await.take() {
        let _ = tx.send(credential);
    }

    StatusCode::OK
}

/// Extract the public key from a WebAuthn attestation object
///
/// The attestation object is CBOR-encoded and contains:
/// - fmt: attestation format
/// - authData: authenticator data containing the public key
/// - attStmt: attestation statement
///
/// The authData structure:
/// - rpIdHash (32 bytes)
/// - flags (1 byte)
/// - signCount (4 bytes)
/// - attestedCredentialData (variable):
///   - aaguid (16 bytes)
///   - credentialIdLength (2 bytes)
///   - credentialId (credentialIdLength bytes)
///   - credentialPublicKey (CBOR-encoded COSE key)
fn extract_public_key_from_attestation(attestation_b64: &str) -> anyhow::Result<String> {
    use base64::Engine;
    use serde_cbor::Value;

    // Decode base64
    let attestation_bytes = base64::engine::general_purpose::STANDARD.decode(attestation_b64)?;

    // Parse CBOR
    let attestation: Value = serde_cbor::from_slice(&attestation_bytes)?;

    // Extract authData from attestation object
    let auth_data_bytes = match &attestation {
        Value::Map(map) => {
            let auth_data_key = Value::Text("authData".to_string());
            map.get(&auth_data_key)
                .and_then(|v| {
                    if let Value::Bytes(bytes) = v {
                        Some(bytes.clone())
                    } else {
                        None
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("authData not found in attestation object"))?
        }
        _ => anyhow::bail!("Attestation object is not a CBOR map"),
    };

    // Parse authData structure
    // Skip: rpIdHash (32) + flags (1) + signCount (4) = 37 bytes
    if auth_data_bytes.len() < 37 {
        anyhow::bail!("authData too short");
    }

    // Check if attestedCredentialData is present (bit 6 of flags)
    let flags = auth_data_bytes[32];
    if flags & 0x40 == 0 {
        anyhow::bail!("No attested credential data present");
    }

    // Skip to attestedCredentialData: 37 bytes + aaguid (16) + credIdLen (2) = 55
    if auth_data_bytes.len() < 55 {
        anyhow::bail!("authData too short for credential data");
    }

    // Read credential ID length (big-endian u16)
    let cred_id_len = u16::from_be_bytes([auth_data_bytes[53], auth_data_bytes[54]]) as usize;

    // Skip to public key: 55 + credIdLen
    let pub_key_offset = 55 + cred_id_len;
    if auth_data_bytes.len() < pub_key_offset {
        anyhow::bail!("authData too short for public key");
    }

    // Parse COSE key (CBOR-encoded)
    let cose_key: Value = serde_cbor::from_slice(&auth_data_bytes[pub_key_offset..])?;

    // Extract x and y coordinates from COSE key
    // COSE key format for ES256:
    // -1 (crv): 1 (P-256)
    // -2 (x): 32 bytes
    // -3 (y): 32 bytes
    let (x_coord, y_coord) = match &cose_key {
        Value::Map(map) => {
            let x_key = Value::Integer(-2);
            let y_key = Value::Integer(-3);

            let x = map
                .get(&x_key)
                .and_then(|v| {
                    if let Value::Bytes(bytes) = v {
                        Some(bytes.clone())
                    } else {
                        None
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("x coordinate not found in COSE key"))?;

            let y = map
                .get(&y_key)
                .and_then(|v| {
                    if let Value::Bytes(bytes) = v {
                        Some(bytes.clone())
                    } else {
                        None
                    }
                })
                .ok_or_else(|| anyhow::anyhow!("y coordinate not found in COSE key"))?;

            (x, y)
        }
        _ => anyhow::bail!("COSE key is not a CBOR map"),
    };

    // Construct uncompressed public key: 0x04 || x || y (65 bytes total)
    let mut public_key = Vec::with_capacity(65);
    public_key.push(0x04); // Uncompressed point indicator
    public_key.extend_from_slice(&x_coord);
    public_key.extend_from_slice(&y_coord);

    if public_key.len() != 65 {
        anyhow::bail!(
            "Invalid public key length: expected 65 bytes, got {}",
            public_key.len()
        );
    }

    // Return as base64
    Ok(base64::engine::general_purpose::STANDARD.encode(&public_key))
}

// Shared handlers

async fn success_handler() -> Html<&'static str> {
    Html(html::success_page())
}
