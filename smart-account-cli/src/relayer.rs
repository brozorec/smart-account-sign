use anyhow::Result;
use colored::Colorize;
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

    eprintln!(
        "\n{}",
        "Preparing request for relayer service...".bright_cyan()
    );

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
        eprintln!("\n{}", "❌ Relayer Error:".red().bold());
        eprintln!("{}", error_text.red());
        eprintln!("\n{}", "Troubleshooting:".yellow().bold());
        eprintln!("  {} Verify your API key is valid", "•".yellow());
        eprintln!(
            "  {} Ensure the transaction is properly authorized",
            "•".yellow()
        );
        anyhow::bail!("Relayer request failed");
    }

    let relayer_response: RelayerResponse = response.json().await?;

    if relayer_response.success {
        eprintln!("\n{}", "✓ Relayer accepted the transaction".green().bold());

        if let Some(data) = &relayer_response.data {
            eprintln!("\n{}", "Transaction Details:".bright_white().bold());
            eprintln!("  {}", data.hash.cyan());
            eprintln!("  Status: {}", data.status.bright_white());
            eprintln!("  Transaction ID: {}", data.transaction_id.bright_white());
        }
    } else {
        eprintln!("\n{}", "⚠️  Relayer reported an issue".yellow().bold());

        if let Some(error) = &relayer_response.error {
            eprintln!("\n{}", "Error details:".red().bold());
            eprintln!("{}", serde_json::to_string_pretty(error)?);
        }
    }

    Ok(relayer_response)
}
