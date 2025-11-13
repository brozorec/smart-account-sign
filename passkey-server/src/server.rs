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
    // For now, we'll extract basic info
    // In a full implementation, you'd parse the attestationObject to get the public key
    let credential = PasskeyCredential {
        credential_id: payload.credential_id.clone(),
        public_key: payload.credential_id.clone(), // Simplified - should parse attestation
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

// Shared handlers

async fn success_handler() -> Html<&'static str> {
    Html(html::success_page())
}
