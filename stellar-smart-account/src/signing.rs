// SPDX-License-Identifier: MIT
// Copyright (c) 2025

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use colored::Colorize;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use stellar_xdr::curr::{
    ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits, PublicKey,
    ScAddress, ScBytes, ScMap, ScVal, ScVec, SorobanAddressCredentials, SorobanAuthorizationEntry,
    SorobanAuthorizedInvocation, SorobanCredentials, VecM, WriteXdr,
};

use crate::smart_account::{ContextRule, Signer as ContextSigner};

const WEBAUTHN_RP_ID: &str = "localhost";

/// Build authorization entries for a smart account invocation
pub async fn build_auth_entries(
    smart_account_addr: &str,
    network_passphrase: &str,
    invocation: SorobanAuthorizedInvocation,
    nonce: i64,
    signature_expiration_ledger: u32,
    selected_rule: &ContextRule,
) -> Result<Vec<SorobanAuthorizationEntry>> {
    // Parse smart account address
    let contract_addr = stellar_strkey::Contract::from_string(smart_account_addr)
        .context("Invalid smart account address")?;
    let smart_account_address = ScAddress::Contract(ContractId(Hash(contract_addr.0)));

    // Calculate network ID
    let network_id = Sha256::digest(network_passphrase.as_bytes());

    // Build credentials
    let mut creds = SorobanAddressCredentials {
        address: smart_account_address,
        nonce,
        signature_expiration_ledger,
        signature: ScVal::Map(None),
    };

    eprintln!(
        "\n{}",
        "[3/5] ✍️  Collecting Signatures".bright_blue().bold()
    );
    eprintln!("\n{}", "Transaction details:".bright_white().bold());
    eprintln!("{}", serde_json::to_string_pretty(&invocation)?);

    // Build the payload that the network will expect to be signed
    let payload = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id.into()),
        nonce,
        signature_expiration_ledger,
        invocation: invocation.clone(),
    });
    let selected_rule_id = selected_rule
        .id
        .context("Selected context rule is missing an ID")?;
    let context_rule_ids = [selected_rule_id];
    let payload_xdr = payload.to_xdr(Limits::none())?;
    let payload_hash = Sha256::digest(payload_xdr);
    let auth_digest = build_auth_digest(&payload_hash, &context_rule_ids)?;
    eprintln!(
        "\n{} {}",
        "Authorization digest to sign:".bright_white().bold(),
        hex::encode(&auth_digest).cyan()
    );

    // Collect signatures from signers
    let signatures = collect_signatures(&selected_rule.signers, &auth_digest).await?;

    if signatures.is_empty() {
        if !selected_rule.policies.is_empty() {
            eprintln!(
                "\n{}",
                "⚠️  No signatures provided! Authorization will be based only on policies."
                    .yellow()
                    .bold()
            );
        } else {
            eprintln!(
                "\n{}",
                "❌ No signatures provided and no policies configured."
                    .red()
                    .bold()
            );
            anyhow::bail!("Authorization is impossible without signatures or policies!\n");
        }
    } else {
        eprintln!(
            "\n{} Collected {} signature(s) successfully",
            "✓".green(),
            signatures.len().to_string().bright_white().bold()
        );
    }

    let sig_map = ScVal::Map(Some(ScMap::sorted_from(signatures)?));
    creds.signature = build_auth_payload_signature(sig_map, &context_rule_ids)?;

    // Build the authorization entry
    let auth_entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(creds),
        root_invocation: invocation,
    };

    Ok(vec![auth_entry])
}

/// Encode `context_rule_ids` exactly as the smart account does on-chain:
/// Soroban's `Vec<u32>::to_xdr(e)` serializes the host value as an `ScVal`,
/// i.e. `ScVal::Vec(Some(ScVec([ScVal::U32(id), ...])))`.
fn context_rule_ids_scval(context_rule_ids: &[u32]) -> Result<ScVal> {
    Ok(ScVal::Vec(Some(ScVec(VecM::try_from(
        context_rule_ids
            .iter()
            .copied()
            .map(ScVal::U32)
            .collect::<Vec<_>>(),
    )?))))
}

/// The smart account binds the selected rule IDs into the signed digest:
/// `auth_digest = sha256(signature_payload || context_rule_ids.to_xdr(e))`
fn build_auth_digest(signature_payload: &[u8], context_rule_ids: &[u32]) -> Result<Vec<u8>> {
    let context_rule_ids_xdr = context_rule_ids_scval(context_rule_ids)?.to_xdr(Limits::none())?;
    let mut preimage = Vec::with_capacity(signature_payload.len() + context_rule_ids_xdr.len());
    preimage.extend_from_slice(signature_payload);
    preimage.extend_from_slice(&context_rule_ids_xdr);
    Ok(Sha256::digest(preimage).to_vec())
}

/// Build the `AuthPayload` struct expected by `__check_auth`:
/// `{ context_rule_ids: Vec<u32>, signers: Map<Signer, Bytes> }`
fn build_auth_payload_signature(sig_map: ScVal, context_rule_ids: &[u32]) -> Result<ScVal> {
    Ok(ScVal::Map(Some(ScMap::sorted_from([
        (
            ScVal::Symbol("context_rule_ids".try_into().unwrap()),
            context_rule_ids_scval(context_rule_ids)?,
        ),
        (ScVal::Symbol("signers".try_into().unwrap()), sig_map),
    ])?)))
}

/// Collect signatures from signers by prompting for private keys
async fn collect_signatures(
    signers: &[ContextSigner],
    payload_hash: &[u8],
) -> Result<Vec<(ScVal, ScVal)>> {
    let mut signatures = Vec::new();

    for (i, signer) in signers.iter().enumerate() {
        let signer_type = signer.signer_type.to_string();

        if signer_type == "Delegated" {
            eprintln!(
                "\n{} {}",
                "⚠️  Signer".yellow(),
                format!(
                    "{i} is a Delegated signer — not supported by this CLI yet, skipping."
                )
                .yellow()
            );
            continue;
        }

        let address_str = match &signer.address {
            ScAddress::Contract(contract_id) => {
                stellar_strkey::Contract(contract_id.0.clone().into()).to_string()
            }
            ScAddress::Account(account_id) => match &account_id.0 {
                PublicKey::PublicKeyTypeEd25519(uint256) => {
                    stellar_strkey::ed25519::PublicKey(uint256.0).to_string()
                }
            },
            _ => "Unsupported address type".to_string(),
        };

        // Box header
        let box_width = 100;
        eprintln!();
        eprintln!(
            "{}",
            format!("+-{:-<width$}-+", "", width = box_width).yellow()
        );
        eprintln!(
            "{}",
            format!("| {:<width$} |", format!("Signer {i}",), width = box_width).yellow()
        );
        eprintln!(
            "{}",
            format!("+-{:-<width$}-+", "", width = box_width).yellow()
        );

        eprintln!("{}  {}", "Type:".bright_white(), signer_type.green());
        eprintln!("{}  {}", "Address:".bright_white(), address_str);
        if let Some(ref pubkey) = signer.public_key {
            eprintln!(
                "{}  {}",
                "Public Key:".bright_white(),
                hex::encode(&pubkey.0).bright_black()
            );
        }
        eprintln!(
            "{}",
            format!("+-{:-<width$}-+", "", width = box_width).yellow()
        );

        eprintln!(
            "\n{}",
            "📌 How to provide this signature:".bright_white().bold()
        );
        eprintln!(
            "   {} Ed25519: Sign with a private key (64 hex characters)",
            "1 →".cyan()
        );
        eprintln!(
            "   {} Passkey: Sign using browser WebAuthn (fingerprint/Face ID)",
            "2 →".cyan()
        );
        eprintln!("   {} Skip this signer", "[Any other key] →".bright_black());
        eprint!("\n{} ", "Your choice:".bright_white().bold());
        io::stderr().flush()?;

        let mut key_type_input = String::new();
        io::stdin().read_line(&mut key_type_input)?;
        let key_type_choice = key_type_input.trim();

        match key_type_choice {
            "1" => match sign_with_ed25519(signer, payload_hash) {
                Ok(el) => signatures.push(el),
                Err(e) => anyhow::bail!("Ed25519 signing failed: {}", e),
            },
            "2" => match sign_with_web_passkey(signer, payload_hash).await {
                Ok(el) => signatures.push(el),
                Err(e) => anyhow::bail!("Passkey signing failed: {}", e),
            },
            _ => {
                eprintln!("  {}", "→ Skipped this signer.".yellow());
            }
        }
    }

    Ok(signatures)
}

/// Sign with a web-based passkey using browser WebAuthn API
async fn sign_with_web_passkey(
    signer: &ContextSigner,
    payload_hash: &[u8],
) -> Result<(ScVal, ScVal)> {
    eprintln!("\n{}", "🌐 Passkey Authentication".bright_magenta().bold());
    eprintln!("\nA browser window will open for you to authenticate.");
    eprintln!("Use your registered passkey (fingerprint, Face ID, or security key).");

    // The verifier's key data holds the 65-byte uncompressed secp256r1 public
    // key, optionally followed by the credential ID. Only the first 65 bytes
    // are the cryptographic key used to look up the local credential.
    let key_data = signer
        .public_key
        .as_ref()
        .ok_or_else(|| {
            anyhow::anyhow!("Passkey signing requires a public key, but none was provided")
        })?
        .0
        .as_slice();
    if key_data.len() < 65 {
        anyhow::bail!(
            "WebAuthn key data must contain a 65-byte public key, got {} bytes",
            key_data.len()
        );
    }
    let public_key = &key_data[..65];
    let pubkey_hex = hex::encode(public_key);

    eprintln!("\n{}", "Authentication details:".bright_white().bold());
    eprintln!("  Domain (RP ID): {}", WEBAUTHN_RP_ID.cyan());
    eprintln!(
        "  Public Key: {}...{}",
        &pubkey_hex[..16].bright_black(),
        &pubkey_hex[pubkey_hex.len() - 16..].bright_black()
    );
    eprintln!(
        "\n{}",
        "⏳ Waiting for browser authentication...".bright_blue()
    );

    // Call the passkey server library (it will lookup credential ID from storage)
    let assertion =
        passkey_server::sign_with_passkey(payload_hash, public_key, WEBAUTHN_RP_ID).await?;

    // Decode the base64-encoded fields
    let signature_der = base64.decode(&assertion.signature)?;
    let authenticator_data_bytes = base64.decode(&assertion.authenticator_data)?;
    let client_data_bytes = base64.decode(&assertion.client_data_json)?;

    // Convert DER-encoded signature to raw format and normalize to low-S form
    let signature_bytes = normalize_ecdsa_signature(&signature_der)?;

    // Build the signature object as a map with authenticator_data, client_data, and signature
    let sig_obj = ScVal::Map(Some(ScMap::sorted_from([
        (
            ScVal::Symbol("authenticator_data".try_into().unwrap()),
            ScVal::Bytes(ScBytes(authenticator_data_bytes.try_into()?)),
        ),
        (
            ScVal::Symbol("client_data".try_into().unwrap()),
            ScVal::Bytes(ScBytes(client_data_bytes.try_into()?)),
        ),
        (
            ScVal::Symbol("signature".try_into().unwrap()),
            ScVal::Bytes(ScBytes(signature_bytes.try_into()?)),
        ),
    ])?));

    // Encode the signature object to XDR bytes
    let sig_obj_xdr = sig_obj.to_xdr(Limits::none())?;

    // Format signature for Stellar smart account: map[signer -> XDR(sig_obj)]
    let key = ScVal::Vec(Some(ScVec(signer.signer_vec.clone())));
    let val = ScVal::Bytes(ScBytes(sig_obj_xdr.try_into()?));

    eprintln!("  {}", "✓ Successfully signed with passkey!".green().bold());
    Ok((key, val))
}

/// Sign with Ed25519 private key
fn sign_with_ed25519(signer: &ContextSigner, payload_hash: &[u8]) -> Result<(ScVal, ScVal)> {
    eprintln!(
        "\n{}",
        "🔑 Ed25519 Signature Required".bright_magenta().bold()
    );
    eprintln!("Enter your 32-byte private key as 64 hex characters.");
    eprintln!(
        "{} {}",
        "Example:".bright_black(),
        "0000000000000000000000000000000000000000000000000000000000000000".bright_black()
    );
    eprint!("\n{} ", "Private key (hex):".bright_white().bold());
    io::stderr().flush()?;

    let mut private_key_input = String::new();
    io::stdin().read_line(&mut private_key_input)?;
    let private_key_str = private_key_input.trim();

    let key_bytes = hex::decode(private_key_str)
        .context("Invalid hex format. Please enter exactly 64 hexadecimal characters.")?;

    if key_bytes.len() != 32 {
        anyhow::bail!(
            "Private key must be exactly 32 bytes (64 hex characters). You provided {} bytes.",
            key_bytes.len()
        );
    }

    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);

    let signing_key = SigningKey::from_bytes(&key_array);
    let verifying_key = signing_key.verifying_key();

    if let Some(ref expected_pubkey) = signer.public_key {
        if verifying_key.to_bytes() != expected_pubkey.0.as_slice() {
            eprintln!(
                "\n{}",
                "❌ Error: The private key does not match the expected public key."
                    .red()
                    .bold()
            );
            eprintln!(
                "Expected public key: {}",
                hex::encode(&expected_pubkey.0).cyan()
            );
            eprintln!(
                "Derived public key: {}",
                hex::encode(verifying_key.to_bytes()).red()
            );
            anyhow::bail!("Private key and public key mismatch");
        }
    }

    let signature = signing_key.sign(payload_hash);
    let key = ScVal::Vec(Some(ScVec(signer.signer_vec.clone())));
    let val = ScVal::Bytes(ScBytes(signature.to_bytes().try_into()?));

    eprintln!(
        "  {}",
        "✓ Successfully signed with Ed25519 key!".green().bold()
    );
    Ok((key, val))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_rule_ids_encode_as_scval_vec() {
        // Must match soroban-sdk's `Vec<u32>::to_xdr(e)`, which serializes the
        // host vector as an ScVal, NOT as a bare XDR `VecM<u32>`.
        let xdr = context_rule_ids_scval(&[7])
            .unwrap()
            .to_xdr(Limits::none())
            .unwrap();
        assert_eq!(
            xdr,
            [
                0, 0, 0, 16, // SCV_VEC
                0, 0, 0, 1, // Some
                0, 0, 0, 1, // length
                0, 0, 0, 3, // SCV_U32
                0, 0, 0, 7, // value
            ]
        );
    }
}

/// Convert DER-encoded ECDSA signature to raw format and normalize to low-S form
///
/// WebAuthn returns DER-encoded signatures, but Stellar verifiers expect raw 64-byte
/// signatures (r || s) with s normalized to the lower half of the curve order.
///
/// DER format: 0x30 [total-length] 0x02 [r-length] [r] 0x02 [s-length] [s]
/// Raw format: [r (32 bytes)] [s (32 bytes)]
fn normalize_ecdsa_signature(der_signature: &[u8]) -> Result<Vec<u8>> {
    use p256::ecdsa::Signature;

    // Parse DER signature
    let signature = Signature::from_der(der_signature)
        .map_err(|e| anyhow::anyhow!("Failed to parse DER signature: {}", e))?;

    // Normalize to low-S form (s must be in lower half of curve order)
    let normalized = signature.normalize_s().unwrap_or(signature);

    // Convert to raw bytes (r || s, 64 bytes total)
    let raw_bytes = normalized.to_bytes();

    Ok(raw_bytes.to_vec())
}
