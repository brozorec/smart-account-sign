//! Standalone passkey server binary

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as base64, Engine as _};
use clap::{Parser, Subcommand};
use passkey_server::{register_passkey, sign_with_passkey, CredentialStorage};

#[derive(Parser)]
#[command(name = "passkey-server")]
#[command(about = "WebAuthn passkey server for CLI authentication")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Register a new passkey
    Register {
        /// User ID
        #[arg(long)]
        user_id: String,

        /// User display name
        #[arg(long)]
        user_name: String,

        /// Relying Party ID
        #[arg(long, default_value = "localhost")]
        rp_id: String,

        /// Save credential to storage
        #[arg(long)]
        save: bool,
    },

    /// Sign with an existing passkey
    Sign {
        /// Challenge to sign (hex encoded)
        #[arg(long)]
        challenge: String,

        /// Public key (hex encoded) to lookup credential
        #[arg(long)]
        public_key: String,

        /// Relying Party ID
        #[arg(long, default_value = "localhost")]
        rp_id: String,
    },

    /// List stored credentials
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Register {
            user_id,
            user_name,
            rp_id,
            save,
        } => {
            println!("🔑 Registering new passkey...");
            let credential = register_passkey(&user_id, &user_name, &rp_id).await?;

            println!("\n✓ Passkey registered successfully!");
            println!("\nCredential ID: {}", credential.credential_id);
            println!("Public Key:    {}", credential.public_key);
            println!("RP ID:         {}", credential.rp_id);
            println!(
                "User:          {} ({})",
                credential.user_name, credential.user_id
            );
            println!("Created:       {}", credential.created_at);

            if save {
                let storage = CredentialStorage::new()?;

                // Decode base64 to get hex representation
                let credential_id_bytes = base64.decode(&credential.credential_id)?;
                let public_key_bytes = base64.decode(&credential.public_key)?;

                let stored = passkey_server::StoredCredential {
                    credential_id: credential.credential_id.clone(),
                    credential_id_hex: hex::encode(&credential_id_bytes),
                    public_key: credential.public_key.clone(),
                    public_key_hex: hex::encode(&public_key_bytes),
                    rp_id: credential.rp_id.clone(),
                    user_id: credential.user_id.clone(),
                    user_name: credential.user_name.clone(),
                    created_at: credential.created_at.clone(),
                };
                storage.save_credential(&stored)?;
                println!("\n💾 Credential saved to storage");
                println!("    Credential ID (hex): {}", stored.credential_id_hex);
                println!("    Public Key (hex):    {}", stored.public_key_hex);
            }
        }

        Commands::Sign {
            challenge,
            public_key,
            rp_id,
        } => {
            println!("🔐 Signing with passkey...");
            let challenge_bytes = hex::decode(&challenge)?;
            let public_key_bytes = hex::decode(&public_key)?;

            let assertion = sign_with_passkey(&challenge_bytes, &public_key_bytes, &rp_id).await?;

            println!("\n✓ Signed successfully!");
            println!("\nSignature:          {}", assertion.signature);
            println!("Authenticator Data: {}", assertion.authenticator_data);
            println!("Client Data JSON:   {}", assertion.client_data_json);
        }

        Commands::List => {
            let storage = CredentialStorage::new()?;
            let credentials = storage.list_credentials()?;

            if credentials.is_empty() {
                println!("No stored credentials found");
            } else {
                println!("Stored credentials:\n");
                for cred in credentials {
                    println!("Credential ID (base64): {}", cred.credential_id);
                    println!("Credential ID (hex):    {}", cred.credential_id_hex);
                    println!("Public Key (hex):       {}", cred.public_key_hex);
                    println!(
                        "  User:                 {} ({})",
                        cred.user_name, cred.user_id
                    );
                    println!("  RP ID:                {}", cred.rp_id);
                    println!("  Created:              {}", cred.created_at);
                    println!();
                }
            }
        }
    }

    Ok(())
}
