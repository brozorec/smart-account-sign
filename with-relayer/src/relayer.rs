use anyhow::Result;
use serde::{Deserialize, Serialize};
use stellar_xdr::curr::{HostFunction, Limits, SorobanAuthorizationEntry, WriteXdr};

#[derive(Serialize)]
struct RelayerRequest {
    params: RelayerParams,
}

#[derive(Serialize)]
struct RelayerParams {
    func: String,
    auth: Vec<String>,
}

#[derive(Deserialize, Debug)]
pub struct RelayerResponse {
    pub success: bool,
    pub data: Option<TransactionData>,
    pub error: Option<serde_json::Value>,
}

#[derive(Deserialize, Debug)]
pub struct TransactionData {
    pub hash: String,
    pub status: String,
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
}

/// Send a HostFunction to the OpenZeppelin relayer
pub async fn send_to_relayer(
    api_key: &str,
    host_function: &HostFunction,
    auth_entries: Vec<SorobanAuthorizationEntry>,
) -> Result<RelayerResponse> {
    let client = reqwest::Client::new();

    // Encode HostFunction to base64 XDR
    let func_xdr = host_function.to_xdr_base64(Limits::none())?;

    // Encode auth entries to base64 XDR
    let auth_xdr: Result<Vec<String>> = auth_entries
        .iter()
        .map(|entry| entry.to_xdr_base64(Limits::none()).map_err(Into::into))
        .collect();

    // Build request payload
    let payload = RelayerRequest {
        params: RelayerParams {
            func: func_xdr,
            auth: auth_xdr?,
        },
    };

    eprintln!("\nSending request to relayer...");
    eprintln!("Payload: {}", serde_json::to_string_pretty(&payload)?);

    // Make POST request
    let response = client
        .post("https://channels.openzeppelin.com/testnet")
        .header("Authorization", format!("Bearer {}", api_key))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    let status = response.status();

    if !status.is_success() {
        let error_text = response.text().await?;
        anyhow::bail!("Relayer request failed: {}", error_text);
    }

    let relayer_response: RelayerResponse = response.json().await?;
    eprintln!("Success: {}", relayer_response.success);

    if let Some(data) = &relayer_response.data {
        eprintln!("\nTransaction Data:");
        eprintln!("  Hash: {}", data.hash);
        eprintln!("  Status: {}", data.status);
        eprintln!("  Transaction ID: {}", data.transaction_id);
    }

    if let Some(error) = &relayer_response.error {
        eprintln!("\nError: {}", serde_json::to_string_pretty(error)?);
    }

    Ok(relayer_response)
}
