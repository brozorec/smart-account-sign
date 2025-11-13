# Passkey Server

Web-based passkey authentication server for CLI tools using WebAuthn.

## Overview

This library provides a web-based flow for passkey authentication that works from CLI environments. It starts a local HTTP server, opens a browser for WebAuthn operations (Touch ID, Face ID, or security keys), and returns the results to the CLI.

## Features

- ✅ **Web-based authentication** - Works from any CLI environment
- ✅ **Platform authenticators** - Touch ID, Face ID, Windows Hello
- ✅ **Hardware keys** - YubiKey, SoloKey, etc.
- ✅ **Library + Binary** - Use as a library or standalone tool
- ✅ **Credential storage** - Optional local storage for credentials
- ✅ **Auto-browser opening** - Automatically opens default browser

## Usage

### As a Library

```rust
use passkey_server::{sign_with_passkey, register_passkey};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Register a new passkey
    let credential = register_passkey(
        "alice@stellar.org",
        "Alice",
        "webauthn.io"
    ).await?;
    
    println!("Credential ID: {}", credential.credential_id);
    println!("Public Key: {}", credential.public_key);
    
    // Sign with the passkey
    let challenge = b"transaction_hash_here";
    let assertion = sign_with_passkey(
        challenge,
        &hex::decode(&credential.credential_id)?,
        "webauthn.io"
    ).await?;
    
    println!("Signature: {}", assertion.signature);
    
    Ok(())
}
```

### As a Standalone Binary

```bash
# Register a new passkey
cargo run --bin passkey-server -- register \
  --user-id alice@stellar.org \
  --user-name Alice \
  --rp-id webauthn.io \
  --save

# Sign with a passkey
cargo run --bin passkey-server -- sign \
  --challenge e2fc660db2a95b5d73e5c2e15ad3935c0db8caa9c9f3ed30b7a0ebee9e705b2f \
  --credential-id 3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29 \
  --rp-id webauthn.io

# List stored credentials
cargo run --bin passkey-server -- list
```

## How It Works

### Signing Flow

```
┌─────────────┐
│   CLI Tool  │  1. Call sign_with_passkey()
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ HTTP Server │  2. Start on localhost:3000
│ (this crate)│  3. Open browser
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   Browser   │  4. User authenticates
│  WebAuthn   │     (Touch ID/Security Key)
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ HTTP Server │  5. Receive signature
└──────┬──────┘
       │
       ▼
┌─────────────┐
│   CLI Tool  │  6. Return signature
└─────────────┘
```

### Registration Flow

Same as signing, but creates a new credential instead of using an existing one.

## API Reference

### `sign_with_passkey`

```rust
pub async fn sign_with_passkey(
    challenge: &[u8],
    credential_id: &[u8],
    rp_id: &str,
) -> Result<PasskeyAssertion>
```

Sign a challenge using a web-based passkey flow.

**Returns:** `PasskeyAssertion` containing:
- `signature` - Base64-encoded signature
- `authenticator_data` - Base64-encoded authenticator data
- `client_data_json` - Base64-encoded client data
- `credential_id` - Base64-encoded credential ID

### `register_passkey`

```rust
pub async fn register_passkey(
    user_id: &str,
    user_name: &str,
    rp_id: &str,
) -> Result<PasskeyCredential>
```

Register a new passkey credential.

**Returns:** `PasskeyCredential` containing:
- `credential_id` - Hex-encoded credential ID
- `public_key` - Hex-encoded public key
- `public_key_algorithm` - Algorithm identifier (-7 for ES256)
- `rp_id` - Relying Party ID
- `user_id` - User identifier
- `user_name` - User display name
- `created_at` - ISO 8601 timestamp

### `CredentialStorage`

```rust
pub struct CredentialStorage;

impl CredentialStorage {
    pub fn new() -> Result<Self>;
    pub fn save_credential(&self, credential: &StoredCredential) -> Result<()>;
    pub fn load_credential(&self, credential_id: &str) -> Result<StoredCredential>;
    pub fn list_credentials(&self) -> Result<Vec<StoredCredential>>;
    pub fn delete_credential(&self, credential_id: &str) -> Result<()>;
}
```

## Storage

Credentials are stored in platform-specific directories:

- **macOS**: `~/Library/Application Support/org.stellar.passkeys/`
- **Linux**: `~/.local/share/passkeys/`
- **Windows**: `C:\Users\<user>\AppData\Roaming\stellar\passkeys\`

Each credential is stored as a JSON file named `<credential-id>.json`.

## Configuration

The server runs on `localhost:3000` by default. This is hardcoded but can be changed in `src/server.rs`.

Timeout for user interaction is 5 minutes (300 seconds).

## Dependencies

- `axum` - Web framework
- `tokio` - Async runtime
- `webbrowser` - Browser integration
- `tower-http` - CORS support
- `serde` / `serde_json` - Serialization
- `base64` / `hex` - Encoding
- `directories` - Platform paths
- `chrono` - Timestamps

## Browser Compatibility

Works with any browser that supports WebAuthn:
- Chrome/Edge 67+
- Firefox 60+
- Safari 13+

## Security Considerations

1. **Localhost only** - Server only binds to 127.0.0.1
2. **Single-use** - Server shuts down after one operation
3. **Timeout** - 5-minute timeout prevents hanging
4. **No persistence** - Server state is ephemeral
5. **CORS enabled** - Required for browser communication

## Troubleshooting

### Browser doesn't open automatically

Manually open: `http://localhost:3000`

### Port 3000 already in use

Kill the process using port 3000 or wait for timeout.

### Credential not found

Ensure the credential ID matches and was created with the same RP ID.

### Touch ID not working

- Ensure macOS 13+ (Ventura or later)
- Check System Settings > Touch ID & Password
- Try in Safari (best WebAuthn support on macOS)

## License

Same as parent workspace.
