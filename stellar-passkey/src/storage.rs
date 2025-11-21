// SPDX-License-Identifier: MIT
// Copyright (c) 2025

//! Credential storage for passkeys

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredential {
    pub credential_id: String,
    pub credential_id_hex: String,
    pub public_key: String,
    pub public_key_hex: String,
    pub rp_id: String,
    pub user_id: String,
    pub user_name: String,
    pub created_at: String,
}

pub struct CredentialStorage {
    storage_dir: PathBuf,
}

impl CredentialStorage {
    pub fn new() -> Result<Self> {
        let storage_dir = directories::ProjectDirs::from("org", "stellar", "passkeys")
            .ok_or_else(|| anyhow::anyhow!("Cannot determine storage directory"))?
            .data_dir()
            .to_path_buf();

        std::fs::create_dir_all(&storage_dir)?;

        Ok(Self { storage_dir })
    }

    pub fn save_credential(&self, credential: &StoredCredential) -> Result<()> {
        // Use hex representation as filename (filesystem-safe)
        let file_path = self
            .storage_dir
            .join(format!("{}.json", credential.credential_id_hex));
        let json = serde_json::to_string_pretty(credential)?;
        std::fs::write(file_path, json)?;
        Ok(())
    }

    pub fn load_credential(&self, credential_id_hex: &str) -> Result<StoredCredential> {
        // Use hex representation for filename lookup
        let file_path = self.storage_dir.join(format!("{}.json", credential_id_hex));
        let json = std::fs::read_to_string(file_path)?;
        let credential = serde_json::from_str(&json)?;
        Ok(credential)
    }

    pub fn list_credentials(&self) -> Result<Vec<StoredCredential>> {
        let mut credentials = Vec::new();
        for entry in std::fs::read_dir(&self.storage_dir)? {
            let entry = entry?;
            if entry.path().extension().and_then(|s| s.to_str()) == Some("json") {
                let json = std::fs::read_to_string(entry.path())?;
                if let Ok(cred) = serde_json::from_str(&json) {
                    credentials.push(cred);
                }
            }
        }
        Ok(credentials)
    }

    pub fn delete_credential(&self, credential_id_hex: &str) -> Result<()> {
        // Use hex representation for filename
        let file_path = self.storage_dir.join(format!("{}.json", credential_id_hex));
        std::fs::remove_file(file_path)?;
        Ok(())
    }
}
