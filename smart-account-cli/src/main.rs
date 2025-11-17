mod relayer;
mod signing;
mod smart_account;
mod transaction;
mod wasm;

use anyhow::Result;
use clap::Parser;
use colored::Colorize;
use rand::Rng;
use soroban_spec_tools::Spec;
use std::io::Write;
use stellar_rpc_client::Client;
use stellar_xdr::curr::{
    ContractId, Hash, HostFunction, InvokeContractArgs, ScAddress, ScSymbol, ScVal,
    SorobanAuthorizationEntry, SorobanAuthorizedFunction, SorobanAuthorizedInvocation, VecM,
};

#[derive(Parser, Debug)]
#[command(
    name = "smart-account-cli",
    version,
    about = "Invoke Stellar smart contract functions using smart account authorization",
    long_about = "A CLI tool for invoking Stellar smart contract functions through a smart account.\n\
                  Smart accounts use custom authorization rules with multiple signers (Ed25519 keys, passkeys, etc.).\n\n\
                  The tool supports two modes:\n\
                  1. Relayer mode (default): Uses OpenZeppelin relayer to sponsor transactions\n\
                  2. Manual mode (--manual): Build and submit transactions directly\n\n\
                  Learn more: https://docs.openzeppelin.com/stellar-contracts/accounts/smart-account",
    after_help = "EXAMPLES:\n\
                  # Using relayer (default mode)\n  \
                  cargo run -p smart-account-cli -- \\\n    \
                  --contract-id CCWAMYJME4WMXZ...\\\n    \
                  --fn-name transfer \\\n    \
                  --fn-args '[\"alice\", \"bob\", \"100\"]' \\\n    \
                  --smart-account GCABC...\n\n  \
                  # Manual mode with source account\n  \
                  cargo run -p smart-account-cli -- \\\n    \
                  --contract-id CCWAMYJME4WMXZ... \\\n    \
                  --fn-name transfer \\\n    \
                  --fn-args '[\"alice\", \"bob\", \"100\"]' \\\n    \
                  --smart-account GCABC... \\\n    \
                  --manual \\\n    \
                  --source-secret SXYZ...\n\n\
                  ENVIRONMENT VARIABLES:\n  \
                  RELAYER_API_KEY    API key for OpenZeppelin relayer (get from https://channels.openzeppelin.com/testnet/gen)\n  \
                  SOURCE_SECRET      Source account secret key for manual mode\n  \
                  SMART_ACCOUNT      Smart account address (alternative to --smart-account flag)"
)]
pub struct Cli {
    /// Stellar RPC endpoint URL
    #[arg(
        long,
        default_value = "https://soroban-testnet.stellar.org",
        env = "RPC_URL"
    )]
    rpc_url: String,

    /// Contract ID to invoke (e.g., CCWAMYJME4WMXZ...)
    #[arg(long, value_name = "CONTRACT_ID")]
    contract_id: String,

    /// Function name to call on the contract
    #[arg(long, value_name = "FUNCTION")]
    fn_name: String,

    /// Function arguments as JSON array (e.g., '["arg1", "arg2"]')
    #[arg(long, value_name = "JSON_ARRAY")]
    fn_args: Vec<String>,

    /// Smart account address (can also use SMART_ACCOUNT env var)
    #[arg(long, env = "SMART_ACCOUNT", value_name = "ADDRESS")]
    smart_account: Option<String>,

    /// API key for OpenZeppelin relayer (can also use RELAYER_API_KEY env var)
    #[arg(long, env = "RELAYER_API_KEY", value_name = "KEY")]
    api_key: Option<String>,

    /// Build and send transaction manually without relayer (requires --source-secret)
    #[arg(long)]
    manual: bool,

    /// Source account secret key for manual mode (can also use SOURCE_SECRET env var)
    #[arg(long, env = "SOURCE_SECRET", value_name = "SECRET")]
    source_secret: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    eprintln!(
        "\n{}",
        "╔═══════════════════════════════════════════════════════════════╗".bright_cyan()
    );
    eprintln!(
        "{}",
        "║         Smart Account Transaction Authorization Tool          ║".bright_cyan()
    );
    eprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════╝".bright_cyan()
    );
    eprintln!(
        "\n{}",
        "This tool helps you invoke contract functions using a smart account.".bright_white()
    );
    eprintln!(
        "{}",
        "Smart accounts use custom authorization rules with multiple signers.".bright_white()
    );
    eprintln!(
        "{}\n",
        "Learn more: https://docs.openzeppelin.com/stellar-contracts/accounts/smart-account".cyan()
    );

    // Validate configuration based on mode
    if cli.manual && cli.source_secret.is_none() {
        eprintln!(
            "\n{}",
            "❌ Missing Configuration for Manual Mode".red().bold()
        );
        eprintln!("\nTo build and send transactions manually, you need a source account.");
        eprintln!("Provide your source account secret key in one of these ways:");
        eprintln!("  {}", "1. Command line: --source-secret SXXX...".yellow());
        eprintln!(
            "  {}",
            "2. Environment:  export SOURCE_SECRET=SXXX...".yellow()
        );
        anyhow::bail!("Missing required source secret");
    } else if !cli.manual && cli.api_key.is_none() {
        eprintln!(
            "\n{}",
            "❌ Missing Configuration for Relayer Mode".red().bold()
        );
        eprintln!("\nTo use the OpenZeppelin relayer service, you need an API key.");
        eprintln!(
            "{}",
            "Get your free API key at: https://channels.openzeppelin.com/testnet/gen".cyan()
        );
        eprintln!("\nThen provide it in one of these ways:");
        eprintln!("  {}", "1. Command line: --api-key YOUR_KEY".yellow());
        eprintln!(
            "  {}",
            "2. Environment:  export RELAYER_API_KEY=YOUR_KEY".yellow()
        );
        eprintln!(
            "\nAlternatively, use {} to sign transactions locally.",
            "--manual mode".cyan()
        );
        anyhow::bail!("Missing required API key");
    }

    let smart_account_addr = match cli.smart_account {
        Some(addr) => addr,
        None => {
            eprintln!(
                "\n{}",
                "📝 Smart Account Address Required".bright_yellow().bold()
            );
            eprintln!("No smart account address provided via --smart-account flag or SMART_ACCOUNT env var.");
            eprintln!(
                "\n{}",
                "Please enter the smart account address:".bright_white()
            );
            eprint!("  {} ", "→".cyan());
            std::io::stdout().flush()?;

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let addr = input.trim().to_string();

            if addr.is_empty() {
                anyhow::bail!("Smart account address cannot be empty");
            }

            addr
        }
    };

    let client = Client::new(&cli.rpc_url)?;
    let network_passphrase = client.get_network().await?.passphrase;

    eprintln!(
        "\n{}",
        "[1/5] 📋 Loading Contract Information".bright_blue().bold()
    );
    eprintln!("Contract: {}", cli.contract_id.bright_white());
    eprintln!("Function: {}", cli.fn_name.bright_white());
    eprintln!("Fetching contract specs from network...");
    let wasm = wasm::get_contract_wasm(&client, &cli.contract_id).await?;
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
        let sc_val = specs
            .from_string(arg_str, &param.type_)
            .map_err(|e| anyhow::anyhow!("Failed to parse argument '{}': {}", arg_str, e))?;
        parsed_args.push(sc_val);
        eprintln!("  {} Arg {}: {}", "✓".green(), i, arg_str.bright_white());
    }

    eprintln!("  {}", "All arguments parsed successfully!".green());

    let invoke_args =
        get_invoke_contract_args(&cli.contract_id, &cli.fn_name, parsed_args.clone())?;

    eprintln!(
        "\n{}",
        "[2/5] 🔐 Smart Account Authorization".bright_blue().bold()
    );
    eprintln!("Smart Account: {}", smart_account_addr.bright_white());
    eprintln!("\nA smart account requires authorization based on configured rules.");
    eprintln!("Each rule defines which signers must approve the transaction.\n");

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
        eprintln!(
            "\n{}",
            "[4/5] 🔨 Building Transaction (Manual Mode)"
                .bright_blue()
                .bold()
        );
        eprintln!("Creating and signing transaction locally with your source account...");
        transaction::send_transaction_manually(
            &client,
            cli.source_secret.as_ref().unwrap(),
            &HostFunction::InvokeContract(invoke_args),
            auth_entries,
        )
        .await?;
    } else {
        eprintln!(
            "\n{}",
            "[4/5] 📡 Submitting to Relayer".bright_blue().bold()
        );
        eprintln!("Sending transaction to OpenZeppelin's relayer service...");
        relayer::send_to_relayer(
            cli.api_key.as_ref().unwrap(),
            &HostFunction::InvokeContract(invoke_args),
            auth_entries,
        )
        .await?;
    }

    eprintln!("\n{}", "[5/5] ✅ Complete!".bright_green().bold());
    eprintln!(
        "\n{}",
        "╔═══════════════════════════════════════════════════════════════╗".bright_green()
    );
    eprintln!(
        "{}",
        "║              Transaction Successfully Submitted!              ║".bright_green()
    );
    eprintln!(
        "{}",
        "╚═══════════════════════════════════════════════════════════════╝".bright_green()
    );
    eprintln!("\n{}", "What happened:".bright_white().bold());
    eprintln!(
        "  {} Contract function invoked via smart account",
        "✓".green()
    );
    eprintln!(
        "  {} Transaction authorized with collected signatures",
        "✓".green()
    );
    eprintln!("  {} Transaction submitted to Stellar network", "✓".green());
    eprintln!("\n{}", "Next steps:".bright_white().bold());
    eprintln!(
        "  {} Check transaction status on Stellar Expert",
        "•".cyan()
    );
    eprintln!(
        "  {} View your transaction in the block explorer\n",
        "•".cyan()
    );

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
