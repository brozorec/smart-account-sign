use anyhow::{Context, Result};
use base64::Engine;
use ed25519_dalek::{Signer as _, SigningKey};
use prettytable::{Cell, Row, Table};
use sha2::{Digest, Sha256};
use std::io::{self, Write};
use stellar_xdr::curr::{
    ContractId, Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits, ScAddress,
    ScBytes, ScMap, ScVal, ScVec, SorobanAddressCredentials, SorobanAuthorizationEntry,
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
        signature: ScVal::Vec(None), // Will be filled with signatures
    };

    eprintln!("\nAuthorizing invocation:");
    eprintln!("{}", serde_json::to_string_pretty(&invocation)?);

    // Build the payload that the network will expect to be signed
    let payload = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network_id.into()),
        nonce,
        signature_expiration_ledger,
        invocation: invocation.clone(),
    });
    let payload_xdr = payload.to_xdr(Limits::none())?;
    let payload_hash = Sha256::digest(payload_xdr);
    eprintln!("\nPayload Hash: {}", hex::encode(payload_hash));

    // Collect signatures from signers
    let signatures = collect_signatures(&selected_rule.signers, &payload_hash).await?;

    if signatures.is_empty() {
        anyhow::bail!("No signatures provided");
    }

    eprintln!("\nCreated {} signature(s)", signatures.len());
    creds.signature = ScVal::Vec(Some(ScVec(VecM::try_from(signatures)?)));

    // Build the authorization entry
    let auth_entry = SorobanAuthorizationEntry {
        credentials: SorobanCredentials::Address(creds),
        root_invocation: invocation,
    };

    Ok(vec![auth_entry])
}

/// Collect signatures from signers by prompting for private keys
async fn collect_signatures(signers: &[ContextSigner], payload_hash: &[u8]) -> Result<Vec<ScVal>> {
    let mut signatures = Vec::new();

    for signer in signers {
        eprintln!("\nSigner found:");
        let mut signer_table = Table::new();
        signer_table.add_row(Row::new(vec![
            Cell::new("Type"),
            Cell::new(&signer.signer_type.to_string()),
        ]));
        signer_table.add_row(Row::new(vec![
            Cell::new("Contract ID"),
            Cell::new(&stellar_strkey::Contract(signer.contract_id.0.clone().into()).to_string()),
        ]));
        signer_table.add_row(Row::new(vec![
            Cell::new("Public Key"),
            Cell::new(&hex::encode(&signer.public_key.0)),
        ]));
        signer_table.printstd();

        eprint!("\nSelect key type:\n  1. Ed25519\n  2. Passkey (Hardware Key - USB/NFC)\n  3. Passkey (Web-based)\n  (or press Enter to skip): ");
        io::stderr().flush()?;

        let mut key_type_input = String::new();
        io::stdin().read_line(&mut key_type_input)?;
        let key_type_choice = key_type_input.trim();

        if !key_type_choice.is_empty() {
            match key_type_choice {
                "1" => {
                    eprint!("Enter Ed25519 private key (hex): ");
                    io::stderr().flush()?;

                    let mut private_key_input = String::new();
                    io::stdin().read_line(&mut private_key_input)?;
                    let private_key_str = private_key_input.trim();

                    if !private_key_str.is_empty() {
                        match hex::decode(private_key_str) {
                            Ok(key_bytes) if key_bytes.len() == 32 => {
                                let mut key_array = [0u8; 32];
                                key_array.copy_from_slice(&key_bytes);

                                let signing_key = SigningKey::from_bytes(&key_array);
                                let verifying_key = signing_key.verifying_key();
                                if verifying_key.to_bytes() != signer.public_key.0.as_slice() {
                                    anyhow::bail!("Mismatch between private key and public key");
                                }
                                let signature = signing_key.sign(payload_hash);
                                let key = ScVal::Vec(Some(ScVec(signer.signer_vec.clone())));
                                let val = ScVal::Bytes(ScBytes(signature.to_bytes().try_into()?));
                                let sig_map = ScVal::Map(Some(ScMap::sorted_from([(key, val)])?));
                                signatures.push(sig_map);
                                eprintln!("✓ Signed with Ed25519 key");
                            }
                            Ok(_) => {
                                anyhow::bail!(
                                    "Private key must be exactly 32 bytes (64 hex characters)"
                                );
                            }
                            Err(e) => {
                                anyhow::bail!("Invalid hex format: {}", e);
                            }
                        }
                    } else {
                        eprintln!("  Skipped");
                    }
                }
                "2" => match sign_with_web_passkey(signer, payload_hash).await {
                    Ok(Some(sig_map)) => {
                        signatures.push(sig_map);
                        eprintln!("✓ Signed with Web Passkey");
                    }
                    Ok(None) => {
                        eprintln!("  Skipped");
                    }
                    Err(e) => {
                        eprintln!("Web passkey signing failed: {}", e);
                        eprintln!("  Skipped");
                    }
                },
                _ => {
                    eprintln!("Invalid choice. Skipped.");
                }
            }
        } else {
            eprintln!("  Skipped");
        }
    }

    Ok(signatures)
}

/// Sign with a web-based passkey using browser WebAuthn API
async fn sign_with_web_passkey(
    signer: &ContextSigner,
    payload_hash: &[u8],
) -> Result<Option<ScVal>> {
    eprintln!("\n🌐 Starting web-based passkey authentication...");

    let credential_id = signer.public_key.0.as_slice();

    eprintln!("  RP ID: {}", WEBAUTHN_RP_ID);
    eprintln!("  Challenge: {}", hex::encode(payload_hash));
    eprintln!("  Credential ID: {}", hex::encode(credential_id));

    // Call the passkey server library
    let assertion =
        passkey_server::sign_with_passkey(payload_hash, credential_id, WEBAUTHN_RP_ID).await?;

    // Decode the base64 signature
    let signature_bytes = base64::engine::general_purpose::STANDARD.decode(&assertion.signature)?;

    eprintln!("✓ Received signature from web authenticator");
    eprintln!("  Signature length: {} bytes", signature_bytes.len());

    // Format signature for Stellar smart account
    let key = ScVal::Vec(Some(ScVec(signer.signer_vec.clone())));
    let val = ScVal::Bytes(ScBytes(signature_bytes.try_into()?));
    let sig_map = ScVal::Map(Some(ScMap::sorted_from([(key, val)])?));

    Ok(Some(sig_map))
}
