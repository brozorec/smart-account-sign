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
  --user-id alice@stellar.org \
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
