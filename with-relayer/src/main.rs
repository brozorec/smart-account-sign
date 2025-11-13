mod relayer;
mod signing;
mod smart_account;
mod transaction;
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
    #[arg(long, default_value = "https://soroban-testnet.stellar.org")]
    rpc_url: String,

    #[arg(long)]
    contract_id: String,

    #[arg(long)]
    fn_name: String,

    #[arg(long)]
    fn_args: Vec<String>,

    #[arg(long)]
    smart_account: Option<String>,

    /// API key for relayer (can also use API_KEY env var)
    #[arg(long)]
    api_key: Option<String>,

    /// Build and send transaction manually (without relayer). Default is to use relayer.
    #[arg(long)]
    manual: bool,

    /// Source account for manual transaction (can also use SOURCE_ACCOUNT env var)
    #[arg(long)]
    source_account: Option<String>,

    /// Source account secret key for manual transaction (can also use SOURCE_SECRET env var)
    #[arg(long)]
    source_secret: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let api_key = cli.api_key.or_else(|| std::env::var("API_KEY").ok());
    let source_account = cli
        .source_account
        .or_else(|| std::env::var("SOURCE_ACCOUNT").ok());
    let source_secret = cli
        .source_secret
        .or_else(|| std::env::var("SOURCE_SECRET").ok());

    // Validate configuration based on mode
    if cli.manual {
        if source_account.is_none() || source_secret.is_none() {
            anyhow::bail!("--source-account and --source-secret are required when using --manual (or set SOURCE_ACCOUNT and SOURCE_SECRET env vars)");
        }
    } else if api_key.is_none() {
        anyhow::bail!("--api-key is required when using relayer mode (or set API_KEY env var)");
    }

    let smart_account_addr = get_required_config(
        cli.smart_account.as_deref(),
        "SMART_ACCOUNT",
        "smart-account",
    )?;

    let client = Client::new(&cli.rpc_url)?;
    let network_passphrase = client.get_network().await?.passphrase;

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
        &network_passphrase,
        invocation,
        nonce,
        current_ledger + 100,
        &selected_rule,
    )
    .await?;

    // Send transaction based on mode
    if cli.manual {
        eprintln!("\n🔨 Building and sending transaction manually...");
        transaction::send_transaction_manually(
            &client,
            source_account.as_ref().unwrap(),
            source_secret.as_ref().unwrap(),
            &HostFunction::InvokeContract(invoke_args),
            auth_entries,
        )
        .await?;
    } else {
        eprintln!("\n📡 Sending to relayer...");
        relayer::send_to_relayer(
            api_key.as_ref().unwrap(),
            &HostFunction::InvokeContract(invoke_args),
            auth_entries,
        )
        .await?;
    }

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
