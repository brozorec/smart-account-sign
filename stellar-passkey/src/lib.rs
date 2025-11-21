// SPDX-License-Identifier: MIT
// Copyright (c) 2025

//! Passkey Server - WebAuthn-based authentication for CLI tools
//!
//! This library provides web-based passkey authentication that works from CLI environments.
//! It starts a local HTTP server, opens a browser for WebAuthn operations, and returns results.

mod html;
mod server;
mod storage;

pub use storage::{CredentialStorage, StoredCredential};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Result from a WebAuthn assertion (signing operation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyAssertion {
    pub signature: String,
    pub authenticator_data: String,
    pub client_data_json: String,
    pub credential_id: String,
}

/// Result from a WebAuthn credential creation (registration)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub credential_id: String,
    pub public_key: String,
    pub public_key_algorithm: i32,
    pub rp_id: String,
    pub user_id: String,
    pub user_name: String,
    pub created_at: String,
}

/// Sign a challenge using a web-based passkey flow
///
/// This function:
/// 1. Looks up the credential ID from storage using the public key
/// 2. Starts a local HTTP server on port 3000
/// 3. Opens the default browser to the authentication page
/// 4. Waits for the user to authenticate with their passkey
/// 5. Returns the signature and authenticator data
///
/// # Arguments
/// * `challenge` - The challenge bytes to sign (e.g., transaction hash)
/// * `public_key` - The public key bytes to lookup the credential
/// * `rp_id` - The Relying Party ID (e.g., "webauthn.io")
///
/// # Returns
/// The assertion containing signature and authenticator data
pub async fn sign_with_passkey(
    challenge: &[u8],
    public_key: &[u8],
    rp_id: &str,
) -> Result<PasskeyAssertion> {
    server::start_sign_server(challenge, public_key, rp_id).await
}

/// Register a new passkey credential using a web-based flow
///
/// This function:
/// 1. Starts a local HTTP server on port 3000
/// 2. Opens the default browser to the registration page
/// 3. Waits for the user to create a new passkey
/// 4. Returns the credential information including public key
///
/// # Arguments
/// * `user_id` - Unique identifier for the user
/// * `user_name` - Display name for the user
/// * `rp_id` - The Relying Party ID (e.g., "webauthn.io")
///
/// # Returns
/// The credential information including credential ID and public key
pub async fn register_passkey(
    user_id: &str,
    user_name: &str,
    rp_id: &str,
) -> Result<PasskeyCredential> {
    server::start_register_server(user_id, user_name, rp_id).await
}
