# Web-Based Passkey Implementation

## What Was Built

```
cli-sign-auth-ed25519/
├── passkey-server/          # Web-based passkey server
│   ├── src/
│   │   ├── lib.rs           # Public API
│   │   ├── server.rs        # HTTP server
│   │   ├── html.rs          # Embedded HTML/JS
│   │   ├── storage.rs       # Credential storage
│   │   └── bin/
│   │       └── passkey-server.rs  # Standalone binary
│   ├── Cargo.toml
│   └── README.md
├── smart-account-cli/       # Uses passkey-server
│   └── src/
│       ├── signing.rs       # Added sign_with_web_passkey()
│       └── main.rs          # Made async
└── Cargo.toml               # UPDATED: Added workspace member
```

## Usage

### Smart Account CLI

The CLI supports two transaction modes:

#### 1. Relayer Mode (Default)

Uses the OpenZeppelin relayer service to submit transactions:

```bash
# Using command-line argument
cargo run -p smart-account-cli -- \
  --contract-id CXXX... \
  --fn-name transfer \
  --fn-args "arg1" \
  --fn-args "arg2" \
  --smart-account CXXX... \
  --api-key YOUR_API_KEY

# Or using environment variable
export RELAYER_API_KEY=your_api_key
cargo run -p smart-account-cli -- \
  --contract-id CXXX... \
  --fn-name transfer \
  --smart-account CXXX...

# When prompted:
# Select key type:
#   1. Ed25519
#   2. Passkey (Web-based)
#   (or press Enter to skip): 2

# Browser opens automatically
# User authenticates with a passkey or Ed25519 secret key
# Transaction submitted via relayer
```

#### 2. Manual Transaction Mode

Builds and signs transactions locally for manual submission:

```bash
# Using command-line arguments
cargo run -p smart-account-cli -- \
  --contract-id CXXX... \
  --fn-name transfer \
  --fn-args "arg1" \
  --fn-args "arg2" \
  --smart-account CXXX... \
  --manual \
  --source-account GXXX... \
  --source-secret SXXX...

# Or using environment variables
export SOURCE_ACCOUNT=GXXX...
export SOURCE_SECRET=SXXX...
cargo run -p smart-account-cli -- \
  --contract-id CXXX... \
  --fn-name transfer \
  --smart-account CXXX... \
  --manual
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

## How It Works

### Signing Flow

1. **CLI calls** `passkey_server::sign_with_passkey()`
2. **Server starts** on `localhost:3000`
3. **Browser opens** to sign page
4. **JavaScript executes** `navigator.credentials.get()`
5. **User authenticates** (Touch ID/Face ID/Security Key)
6. **Browser POSTs** signature to `/callback`
7. **Server returns** signature to CLI
8. **Server shuts down**

### Registration Flow

Same as signing, but uses `navigator.credentials.create()` to generate a new credential.

## Testing

### Build Everything
```bash
cargo build --workspace
```

### Test Passkey Server Standalone
```bash
# Register
cargo run --bin passkey-server -- register \
  --user-id test@example.com \
  --user-name "Test User" \
  --save

# List
cargo run --bin passkey-server -- list
```

### Test with CLI
```bash
cargo run -p smart-account-cli -- \
  --contract-id <CONTRACT_ID> \
  --fn-name <FUNCTION> \
  --smart-account <SMART_ACCOUNT>

# Select option 2 when prompted
```

## Storage Location

Credentials stored at:
- **macOS**: `~/Library/Application Support/org.stellar.passkeys/`
- **Linux**: `~/.local/share/passkeys/`
- **Windows**: `%APPDATA%\stellar\passkeys\`

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
- `--source-account` - Source account public key (or `SOURCE_ACCOUNT` env var)
- `--source-secret` - Source account secret key (or `SOURCE_SECRET` env var)

## Environment Variables

All sensitive values can be provided via environment variables:

```bash
# For relayer mode
export RELAYER_API_KEY=your_api_key
export SMART_ACCOUNT=CXXX...

# For manual mode
export SOURCE_ACCOUNT=GXXX...
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
