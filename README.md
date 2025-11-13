# Web-Based Passkey Implementation

## What Was Built

```
cli-sign-auth-ed25519/
├── passkey-server/          # NEW: Web-based passkey server
│   ├── src/
│   │   ├── lib.rs           # Public API
│   │   ├── server.rs        # HTTP server
│   │   ├── html.rs          # Embedded HTML/JS
│   │   ├── storage.rs       # Credential storage
│   │   └── bin/
│   │       └── passkey-server.rs  # Standalone binary
│   ├── Cargo.toml
│   └── README.md
├── with-relayer/            # UPDATED: Uses passkey-server
│   └── src/
│       ├── signing.rs       # Added sign_with_web_passkey()
│       └── main.rs          # Made async
└── Cargo.toml               # UPDATED: Added workspace member
```

## Features Implemented

### 1. Passkey Server Library

- ✅ **HTTP server** using Axum
- ✅ **Auto-browser opening** with webbrowser crate
- ✅ **WebAuthn signing** via browser API
- ✅ **WebAuthn registration** for new credentials
- ✅ **Credential storage** in platform-specific directories
- ✅ **Timeout handling** (5 minutes)
- ✅ **CORS support** for browser communication

### 2. HTML/JavaScript Pages

- ✅ **Sign page** with `navigator.credentials.get()`
- ✅ **Register page** with `navigator.credentials.create()`
- ✅ **Auto-execution** - starts WebAuthn flow on page load
- ✅ **Modern UI** with status indicators and spinners
- ✅ **Error handling** with user-friendly messages

### 3. CLI Integration

- ✅ **Async signing flow** in `with-relayer`
- ✅ **Option 3** in menu: "Passkey (Web-based)"
- ✅ **Seamless integration** - just calls library function
- ✅ **Base64 decoding** of signatures
- ✅ **Stellar formatting** of signatures

### 4. Standalone Binary

- ✅ **Register command** - Create new passkeys
- ✅ **Sign command** - Sign with existing passkeys
- ✅ **List command** - View stored credentials
- ✅ **CLI arguments** with clap

## Usage

### From with-relayer CLI

```bash
cd /Users/boyan/cli-sign-auth-ed25519
cargo run -p with-relayer -- \
  --contract-id CXXX... \
  --fn-name transfer \
  --fn-args '["arg1"]' \
  --smart-account CXXX...

# When prompted:
# Select key type:
#   1. Ed25519
#   2. Passkey (Hardware Key - USB/NFC)
#   3. Passkey (Web-based)  ← NEW!
#   (or press Enter to skip): 3

# Browser opens automatically
# User authenticates with Touch ID/Face ID/Security Key
# Signature returned to CLI
```

### Standalone Passkey Server

```bash
# Register a new passkey
cargo run --bin passkey-server -- register \
  --user-id alice@stellar.org \
  --user-name Alice \
  --rp-id webauthn.io \
  --save

# Sign with passkey
cargo run --bin passkey-server -- sign \
  --challenge <hex> \
  --credential-id <hex> \
  --rp-id webauthn.io

# List credentials
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

## File Structure

### passkey-server/src/lib.rs
- Public API: `sign_with_passkey()`, `register_passkey()`
- Type definitions: `PasskeyAssertion`, `PasskeyCredential`

### passkey-server/src/server.rs
- HTTP server implementation
- Routes: `/`, `/callback`, `/register`, `/register/callback`, `/success`
- Server lifecycle management

### passkey-server/src/html.rs
- Embedded HTML templates
- WebAuthn JavaScript code
- UI styling

### passkey-server/src/storage.rs
- Credential persistence
- Platform-specific paths
- CRUD operations

### with-relayer/src/signing.rs
- `sign_with_web_passkey()` - Calls passkey server
- `collect_signatures()` - Now async
- `build_auth_entries()` - Now async

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
cargo run -p with-relayer -- \
  --contract-id <CONTRACT_ID> \
  --fn-name <FUNCTION> \
  --smart-account <SMART_ACCOUNT>

# Select option 3 when prompted
```

## Storage Location

Credentials stored at:
- **macOS**: `~/Library/Application Support/org.stellar.passkeys/`
- **Linux**: `~/.local/share/passkeys/`
- **Windows**: `%APPDATA%\stellar\passkeys\`

## Browser Compatibility

- ✅ Chrome/Edge 67+
- ✅ Firefox 60+
- ✅ Safari 13+
