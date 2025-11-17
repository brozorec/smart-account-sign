use anyhow::{Context, Result};
use stellar_rpc_client::Client;
use stellar_xdr::curr::{
    ContractDataDurability, ContractDataEntry, ContractExecutable, ContractId, Hash,
    LedgerEntryData, LedgerKey, LedgerKeyContractCode, LedgerKeyContractData, Limited, Limits,
    ReadXdr, ScAddress, ScVal,
};

/// Fetches the WASM bytecode for a contract from the Stellar network
pub async fn get_contract_wasm(client: &Client, contract_id: &str) -> Result<Vec<u8>> {
    // Convert contract ID to Hash for WASM key lookup
    let contract_addr =
        stellar_strkey::Contract::from_string(contract_id).context("Invalid contract ID")?;

    // Build ledger key for contract instance
    let instance_key = LedgerKey::ContractData(LedgerKeyContractData {
        contract: ScAddress::Contract(ContractId(Hash(contract_addr.0))),
        key: ScVal::LedgerKeyContractInstance,
        durability: ContractDataDurability::Persistent,
    });

    // Query Soroban RPC for contract instance
    let response = client.get_ledger_entries(&[instance_key]).await?;
    let entries = response.entries.context("No entries returned")?;
    let entry_xdr = &entries.first().context("No contract instance found")?.xdr;

    // Parse the ledger entry to get WASM hash
    let entry =
        LedgerEntryData::read_xdr_base64(&mut Limited::new(entry_xdr.as_bytes(), Limits::none()))?;

    let wasm_hash = match entry {
        LedgerEntryData::ContractData(ContractDataEntry { val, .. }) => {
            if let ScVal::ContractInstance(instance) = val {
                instance.executable
            } else {
                anyhow::bail!("Expected ContractInstance")
            }
        }
        _ => anyhow::bail!("Expected ContractData"),
    };

    let wasm_hash_bytes = match wasm_hash {
        ContractExecutable::Wasm(hash) => hash.0,
        _ => anyhow::bail!("Contract not using WASM"),
    };

    // Now fetch the actual WASM code
    let wasm_key = LedgerKey::ContractCode(LedgerKeyContractCode {
        hash: Hash(wasm_hash_bytes),
    });

    let wasm_response = client.get_ledger_entries(&[wasm_key]).await?;
    let wasm_entries = wasm_response.entries.context("No WASM entries")?;
    let wasm_entry_xdr = &wasm_entries.first().context("No WASM found")?.xdr;

    let wasm_entry = LedgerEntryData::read_xdr_base64(&mut Limited::new(
        wasm_entry_xdr.as_bytes(),
        Limits::none(),
    ))?;

    let wasm_bytes = match wasm_entry {
        LedgerEntryData::ContractCode(code_entry) => code_entry.code.to_vec(),
        _ => anyhow::bail!("Expected ContractCode"),
    };

    Ok(wasm_bytes)
}
