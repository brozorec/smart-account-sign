mod relayer;
mod signing;
mod smart_account;
mod wasm;

use anyhow::Result;
use clap::Parser;
use rand::Rng;
use soroban_spec_tools::Spec;
use stellar_rpc_client::Client;
use stellar_xdr::curr::{
    ContractId, Hash, HostFunction, InvokeContractArgs, ScAddress, ScSymbol, ScVal,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, VecM,
};

#[derive(Parser, Debug)]
#[command()]
pub struct Cli {
    #[arg(long, default_value = "Test SDF Network ; September 2015")]
    network_passphrase: String,

    #[arg(long)]
    contract_id: String,

    #[arg(long)]
    fn_name: String,

    #[arg(long)]
    fn_args: Vec<String>,

    #[arg(long)]
    api_key: Option<String>,

    #[arg(long)]
    smart_account: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Get required configuration from CLI or environment
    let api_key = get_required_config(cli.api_key.as_deref(), "RELAYER_API_KEY", "api-key")?;
    let smart_account_addr = get_required_config(
        cli.smart_account.as_deref(),
        "SMART_ACCOUNT",
        "smart-account",
    )?;

    let client = Client::new("https://soroban-testnet.stellar.org")?;

    eprintln!("Fetching contract WASM for: {}", cli.contract_id);
    let wasm = wasm::get_contract_wasm(&client, &cli.contract_id).await?;
    eprintln!("Retrieved WASM ({} bytes)", wasm.len());

    eprintln!("Parsing contract specs...");
    let specs = Spec::from_wasm(&wasm)
        .map_err(|e| anyhow::anyhow!("Failed to parse contract specs: {}", e))?;

    // Find the function in the specs
    let function_spec = specs
        .find_function(&cli.fn_name)
        .map_err(|e| anyhow::anyhow!("Function '{}' not found: {}", cli.fn_name, e))?;

    // Parse function arguments to ScVal
    if cli.fn_args.len() != function_spec.inputs.len() {
        anyhow::bail!(
            "Expected {} arguments, got {}",
            function_spec.inputs.len(),
            cli.fn_args.len()
        );
    }

    let mut parsed_args: Vec<ScVal> = Vec::new();
    for (i, (param, arg_str)) in function_spec
        .inputs
        .iter()
        .zip(cli.fn_args.iter())
        .enumerate()
    {
        eprintln!("\nParsing arg {}: {} (type: {:?})", i, arg_str, param.type_);
        let sc_val = specs
            .from_string(arg_str, &param.type_)
            .map_err(|e| anyhow::anyhow!("Failed to parse argument: {}", e))?;
        parsed_args.push(sc_val);
    }

    eprintln!("\nParsed arguments:");
    eprintln!("{:?}", parsed_args);

    let invoke_args =
        get_invoke_contract_args(&cli.contract_id, &cli.fn_name, parsed_args.clone())?;

    eprintln!("\n=== Smart Account Authorization ===");

    // Fetch and display context rules
    let rules = smart_account::get_context_rules_table(&client, &smart_account_addr).await?;

    // Prompt user to select a rule
    let selected_rule = smart_account::prompt_rule_selection(&rules)?;

    let invocation = SorobanAuthorizedInvocation {
        function: SorobanAuthorizedFunction::ContractFn(invoke_args.clone()),
        sub_invocations: VecM::default(),
    };

    // Generate random nonce
    let mut rng = rand::thread_rng();
    let nonce: i64 = rng.gen();
    eprintln!("\nGenerated nonce: {}", nonce);

    // Get current ledger and calculate signature expiration
    let current_ledger = client.get_latest_ledger().await?.sequence;

    // Build authorization entries with signatures
    let auth_entries: Vec<SorobanAuthorizationEntry> = signing::build_auth_entries(
        &smart_account_addr,
        &cli.network_passphrase,
        invocation,
        nonce,
        current_ledger + 100,
        &selected_rule,
    )?;

    // Send to relayer
    relayer::send_to_relayer(
        &api_key,
        &HostFunction::InvokeContract(invoke_args),
        auth_entries,
    )
    .await?;

    Ok(())
}

fn get_invoke_contract_args(
    contract_id: &str,
    function_name: &str,
    args: Vec<ScVal>,
) -> Result<InvokeContractArgs> {
    // Convert contract ID to ScAddress
    let contract_addr = stellar_strkey::Contract::from_string(contract_id)?;
    let contract_address = ScAddress::Contract(ContractId(Hash(contract_addr.0)));

    Ok(InvokeContractArgs {
        contract_address,
        function_name: ScSymbol(function_name.try_into()?),
        args: args.try_into()?,
    })
}

/// Get required configuration from CLI argument or environment variable
fn get_required_config(cli_value: Option<&str>, env_var: &str, arg_name: &str) -> Result<String> {
    cli_value
        .map(String::from)
        .or_else(|| std::env::var(env_var).ok())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "Missing required configuration: --{} or {} environment variable",
                arg_name,
                env_var
            )
        })
}
