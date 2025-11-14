# Smart Account Sign

An interactive CLI tool for managing and interacting with [OpenZeppelin Stellar Smart Accounts](https://github.com/OpenZeppelin/stellar-contracts/tree/main/packages/accounts).

**Learn more:** [Smart Account Documentation](https://docs.openzeppelin.com/stellar-contracts/accounts/smart-account)

### Features

1. **Visualize Context Rules** - Display all context rules configured on a smart account
2. **Select Context Rules** - Choose which authorization context to use for transactions
3. **Multi-Signer Support** - Authorize transactions using Ed25519 keys or WebAuthn passkeys
4. **Flexible Transaction Submission**:
   - **Relayer Mode**: Submit via OpenZeppelin's managed relayer service
   - **Manual Mode**: Build and sign locally with your own source account
5. **Standalone Passkey Tools** - Separate CLI for passkey registration and testing

## Repo Structure

```
smart-account-sign/
├── passkey-server/          # Web-based passkey server library
│   ├── src/
│   │   ├── lib.rs           # Public API (sign_with_passkey, register_passkey)
│   │   ├── server.rs        # HTTP server with WebAuthn endpoints
│   │   ├── html.rs          # Embedded HTML/JS for browser interaction
│   │   ├── storage.rs       # Platform-specific credential storage
│   │   └── bin/
│   │       └── passkey-server.rs  # Standalone CLI tool
│   ├── Cargo.toml
│   └── README.md
├── smart-account-cli/       # Interactive smart account CLI
│   └── src/
│       ├── main.rs          # CLI entry point and orchestration
│       ├── signing.rs       # Ed25519 and passkey signing logic
│       ├── smart_account.rs # Smart account rule fetching and display
│       ├── transaction.rs   # Manual transaction building
│       ├── relayer.rs       # OpenZeppelin relayer integration
│       └── wasm.rs          # Contract WASM and spec parsing
│   └── Cargo.toml
└── Cargo.toml               # Workspace configuration
```

## Usage

### Smart Account CLI

The CLI supports two transaction modes:

#### 1. Relayer Mode (Default)

Uses [OpenZeppelin's managed relayer service](https://github.com/OpenZeppelin/relayer-plugin-channels) to submit transactions. The relayer handles transaction building, fee management, and submission to the network.

**Generate an API key:**
- **Testnet**: https://channels.openzeppelin.com/testnet/gen
- **Mainnet**: https://channels.openzeppelin.com/gen

Example usage:

```bash
# Using command-line argument
cargo run -p smart-account-cli -- \
  --contract-id CXXX... \
  --fn-name transfer \
  --fn-args "CXXX" \
  --fn-args "GXXX" \
  --fn-args "1000" \
  --smart-account CXXX... \
  --api-key YOUR_API_KEY

# Or using environment variables
export RELAYER_API_KEY=your_api_key
export SMART_ACCOUNT=CXXX...
cargo run -p smart-account-cli -- \
  --contract-id CXXX... \
  --fn-name transfer \
  --fn-args "CXXX" \
  --fn-args "GXXX" \
  --fn-args "1000"

# When prompted:
# Select key type:
#   1. Ed25519
#   2. Passkey (Web-based)
#   (or press any key to skip): 2

# Browser opens automatically
# User authenticates with a passkey or Ed25519 secret key
# Transaction submitted via relayer
```

#### 2. Manual Transaction Mode

Builds and signs transactions locally for manual submission:

```bash
# Using command-line argument
cargo run -p smart-account-cli -- \
  --contract-id CXXX... \
  --fn-name transfer \
  --fn-args "CXXX" \
  --fn-args "GXXX" \
  --fn-args "1000" \
  --smart-account CXXX... \
  --manual \
  --source-secret SXXX...

# Or using environment variables
export SOURCE_SECRET=SXXX...
export SMART_ACCOUNT=CXXX...
cargo run -p smart-account-cli -- \
  --contract-id CXXX... \
  --fn-name transfer \
  --fn-args "CXXX" \
  --fn-args "GXXX" \
  --fn-args "1000" \
  --manual

# Source account is automatically derived from the secret key
```

### Standalone Passkey Server

For testing or standalone passkey operations:

```bash
# Register a new passkey
cargo run --bin passkey-server -- register \
  --user-id alice@example.com \
  --user-name Alice \
  --rp-id localhost \
  --save

# Sign with passkey (using public key)
cargo run --bin passkey-server -- sign \
  --challenge <hex> \
  --public-key <hex> \
  --rp-id localhost

# List stored credentials
cargo run --bin passkey-server -- list
```
For more details about how it works, check its [README](./passkey-server/README.md).

## Example Flow

This example demonstrates a complete fungible token transfer flow on testnet using a smart account configured with two signers: an Ed25519 key and a passkey. We'll walk through deploying a token, setting up a smart account, and transferring tokens using the CLI.

### Prerequisites

Install the [Stellar CLI](https://developers.stellar.org/docs/tools/developer-tools/cli/stellar-cli):
```bash
cargo install --locked stellar-cli
```

Configure Stellar CLI to use testnet:
```bash
stellar network use testnet
```

Build the workspace:
```bash
cd smart-account-sign/
cargo build --workspace
```

### Overview

The flow consists of two main parts:
- **Part A**: Issuer deploys a fungible token and transfers it to the smart account using Stellar CLI
- **Part B**: Smart account transfers tokens to a receiver using this CLI tool

### Step 1: Create and Fund Accounts

Create three accounts for this demo:

```bash
# Generate keypairs
stellar keys generate feepayer
stellar keys generate issuer
stellar keys generate receiver

# Fund accounts on testnet
stellar keys fund feepayer
stellar keys fund issuer
stellar keys fund receiver

# Use feepayer for transactions
stellar keys use feepayer
```

### Step 2: Deploy Fungible Token

Deploy a fungible token contract with the provided wasm hash:

```bash
# Deploy the token contract (using the wasm hash from OpenZeppelin's example "fungible-pausable").
stellar contract deploy \
  --wasm-hash df679337aebe02031bc4a90b767b73c38971fdb382f6051c6f91c7fe94ef66d5 \
  --alias token \
  -- \
  --owner issuer \
  --initial_supply 1000

# Set the newly deployed token address as an environment variable
export TOKEN=TOKEN_ADDRESS

# The `initial_supply` gets minted to issuer
stellar contract invoke --id token -- balance --account issuer
```

### Step 3: Register a Passkey

Register a passkey and note the public key for smart account setup:

```bash
cargo run --bin passkey-server -- register \
  --user-id demo@example.com \
  --user-name "Demo User" \
  --rp-id localhost \
  --save

# List credentials to get the public key
cargo run --bin passkey-server -- list

# Set passkey public key from the output above as an environment variable
export PASSKEY_PUB=65_BYTES_HEX_STRING
```

### Step 4: Deploy Smart Account

Deploy the smart account with two signers:

```bash
stellar contract deploy \
  --alias smart-account \
  --wasm-hash 3d4a5d1f710108a6bca2c2c6fc7ea83d9460e2ca64185663926644a67741022e \
  -- \
  --signers '[
    {
      "External": [
        "CDLDYJWEZSM6IAI4HHPEZTTV65WX4OVN3RZD3U6LQKYAVIZTEK7XYAYT",
        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29"
      ]
    },
    {
      "External": [
        "CDPMNLTCV44P3NIUNVPWL3SICZCHO7XBQ6CAKED4GQPGVG2RB7DMUIAX",
        "'"$(echo -n $PASSKEY_PUB)"'"
      ]
    }
  ]' \
  --policies '{}'

# Set the address of the newly deployed smart account as an environment variable
export SMART_ACCOUNT=SMART_ACCOUNT_ADDRESS
```

#### Notes

1. Verifier Contracts (already deployed on testnet for convenience):
   - **Ed25519 Verifier**: `CDLDYJWEZSM6IAI4HHPEZTTV65WX4OVN3RZD3U6LQKYAVIZTEK7XYAYT`
   - **WebAuthn Verifier**: `CDPMNLTCV44P3NIUNVPWL3SICZCHO7XBQ6CAKED4GQPGVG2RB7DMUIAX`

2. WASM hash from OpenZeppelin's example "mutlisig-smart-account" already uploaded on testnet:
   - `3d4a5d1f710108a6bca2c2c6fc7ea83d9460e2ca64185663926644a67741022e `

3. Test Ed25519 Key:
   - Secret Key: `0000000000000000000000000000000000000000000000000000000000000000`
   - Public Key: `3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29`

### Step 5: Transfer Tokens from Issuer to Smart Account

Transfer tokens from the issuer to the smart account:

```bash
stellar contract invoke \
  --source issuer \
  --id token \
  -- transfer \
  --from $(stellar keys public-key issuer) \
  --to $SMART_ACCOUNT \
  --amount 500

# Verify the balance
stellar contract invoke \
  --source issuer \
  --id token \
  -- balance \
  --account $SMART_ACCOUNT
```

### Step 6: Transfer Tokens from Smart Account Using CLI

Now use this CLI tool to transfer tokens from the smart account to the receiver. The smart account will require authorization from one or both signers.

#### Option A: Using Relayer Mode

Get a Relayer API key from https://channels.openzeppelin.com/testnet/gen

```bash
# Set environment variables
export RELAYER_API_KEY=your_api_key
```

When prompted
1. select ID = 0 for the single Context Rule that's configured
2. about the signing methods for:
   - the 1st signer
      - select **Option 1: Ed25519**
      - enter private key: 0000000000000000000000000000000000000000000000000000000000000000
   - the 2nd signer
      - select **Option 2: Passkey (Web-based)**
      - browser will open for passkey authentication

```bash
# Run the CLI
cargo run -p smart-account-cli -- \
  --contract-id $TOKEN \
  --fn-name transfer \
  --fn-args $SMART_ACCOUNT \
  --fn-args $(stellar keys address receiver) \
  --fn-args 100
```

#### Option B: Using Manual Mode

```bash
# Set environment variables
export SOURCE_SECRET=$(stellar keys public-key feepayer)

# Run the CLI
cargo run -p smart-account-cli -- \
  --contract-id $TOKEN \
  --fn-name transfer \
  --fn-args $SMART_ACCOUNT \
  --fn-args $(stellar keys address receiver) \
  --fn-args 100 \
  --manual
```

### Step 7: Verify the Transfer

Check the receiver's balance to confirm the transfer:

```bash
stellar contract invoke \
  --id token \
  -- balance \
  --account $(stellar keys public-key receiver)
```

You should see the transferred amount (e.g., 100 tokens).

### What Just Happened?

1. **Context Rule Selection**: The CLI fetched all context rules from the smart account and displayed them
2. **Signer Authorization**: You authorized the transaction using:
   - The Ed25519 test key
   - Your registered passkey via browser WebAuthn
3. **Transaction Submission**: The transaction was submitted either:
   - Via the OpenZeppelin relayer (relayer mode)
   - Directly to the network (manual mode)
4. **Smart Account Authorization**: The smart account contract authorized your signatures using the appropriate verifier contract (Ed25519 or WebAuthn)

For more details on smart account architecture, see the [OpenZeppelin Smart Account Documentation](https://docs.openzeppelin.com/stellar-contracts/accounts/smart-account).

## CLI Arguments Reference

### Common Arguments
- `--contract-id` - Contract to invoke
- `--fn-name` - Function name to call
- `--fn-args` - Function arguments (for more than one arg, use subsequent --fn-args)
- `--smart-account` - Smart account address (or `SMART_ACCOUNT` env var)
- `--rpc-url` - RPC endpoint (default: Stellar testnet)

### Relayer Mode (Default)
- `--api-key` - Relayer API key (or `RELAYER_API_KEY` env var)

### Manual Mode
- `--manual` - Build transaction manually (without relayer)
- `--source-secret` - Source account secret key (or `SOURCE_SECRET` env var)
  - Public key is automatically derived from the secret

## Environment Variables

All sensitive values can be provided via environment variables:

```bash
# For relayer mode
export RELAYER_API_KEY=your_api_key
export SMART_ACCOUNT=CXXX...

# For manual mode
export SOURCE_SECRET=SXXX...
export SMART_ACCOUNT=CXXX...
```

## Security Notes

### Relayer Mode
- API key is sent to the relayer service
- Relayer submits the transaction
- No source account credentials needed
- Quick and convenient for development

### Manual Mode
- Source secret key is used locally only
- Transaction is signed locally
- You control when/how to submit
- More secure for sensitive operations
