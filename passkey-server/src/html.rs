//! Embedded HTML pages for WebAuthn operations

/// HTML page for passkey signing (assertion)
pub fn sign_page(challenge: &str, credential_id: &str, rp_id: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sign with Passkey</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
        }}
        .subtitle {{
            color: #666;
            margin-bottom: 30px;
        }}
        .info {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
            font-family: monospace;
            font-size: 12px;
            word-break: break-all;
        }}
        .info-label {{
            font-weight: bold;
            color: #555;
        }}
        button {{
            background: #007bff;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            width: 100%;
            margin-top: 20px;
        }}
        button:hover {{
            background: #0056b3;
        }}
        button:disabled {{
            background: #ccc;
            cursor: not-allowed;
        }}
        .status {{
            margin-top: 20px;
            padding: 15px;
            border-radius: 6px;
            display: none;
        }}
        .status.success {{
            background: #d4edda;
            color: #155724;
            display: block;
        }}
        .status.error {{
            background: #f8d7da;
            color: #721c24;
            display: block;
        }}
        .spinner {{
            border: 3px solid #f3f3f3;
            border-top: 3px solid #007bff;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
            display: none;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 Sign with Passkey</h1>
        <p class="subtitle">Authenticate using your passkey to sign the transaction</p>
        
        <div class="info">
            <div><span class="info-label">RP ID:</span> {rp_id}</div>
            <div><span class="info-label">Challenge:</span> {challenge}</div>
            <div><span class="info-label">Credential ID:</span> {credential_id}</div>
        </div>
        
        <button id="signButton" onclick="signWithPasskey()">
            Sign with Passkey
        </button>
        
        <div class="spinner" id="spinner"></div>
        <div class="status" id="status"></div>
    </div>

    <script>
        const CHALLENGE = "{challenge}";
        const CREDENTIAL_ID = "{credential_id}";
        const RP_ID = "{rp_id}";

        function hexToBytes(hex) {{
            const bytes = new Uint8Array(hex.length / 2);
            for (let i = 0; i < hex.length; i += 2) {{
                bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
            }}
            return bytes;
        }}

        function bytesToBase64(bytes) {{
            return btoa(String.fromCharCode.apply(null, bytes));
        }}

        function showStatus(message, isError = false) {{
            const status = document.getElementById('status');
            status.textContent = message;
            status.className = 'status ' + (isError ? 'error' : 'success');
        }}

        function showSpinner(show) {{
            document.getElementById('spinner').style.display = show ? 'block' : 'none';
            document.getElementById('signButton').disabled = show;
        }}

        async function signWithPasskey() {{
            try {{
                showSpinner(true);
                showStatus('');

                const challengeBytes = hexToBytes(CHALLENGE);
                const credentialIdBytes = hexToBytes(CREDENTIAL_ID);

                const credentialRequestOptions = {{
                    publicKey: {{
                        challenge: challengeBytes,
                        rpId: RP_ID,
                        allowCredentials: [{{
                            type: "public-key",
                            id: credentialIdBytes
                        }}],
                        userVerification: "required",
                        timeout: 60000
                    }}
                }};

                console.log('Requesting assertion...', credentialRequestOptions);
                const assertion = await navigator.credentials.get(credentialRequestOptions);
                console.log('Assertion received:', assertion);

                if (!assertion) {{
                    throw new Error('No assertion returned');
                }}

                const response = assertion.response;
                const result = {{
                    signature: bytesToBase64(new Uint8Array(response.signature)),
                    authenticatorData: bytesToBase64(new Uint8Array(response.authenticatorData)),
                    clientDataJSON: bytesToBase64(new Uint8Array(response.clientDataJSON)),
                    credentialId: bytesToBase64(new Uint8Array(assertion.rawId))
                }};

                console.log('Sending result to server:', result);

                const postResponse = await fetch('/callback', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify(result)
                }});

                if (postResponse.ok) {{
                    showStatus('✓ Successfully signed! You can close this window.');
                    setTimeout(() => window.close(), 2000);
                }} else {{
                    throw new Error('Failed to send result to server');
                }}

            }} catch (error) {{
                console.error('Error:', error);
                showStatus('Error: ' + error.message, true);
            }} finally {{
                showSpinner(false);
            }}
        }}

        // Auto-start on page load
        window.addEventListener('load', () => {{
            setTimeout(signWithPasskey, 500);
        }});
    </script>
</body>
</html>"#,
        challenge = challenge,
        credential_id = credential_id,
        rp_id = rp_id
    )
}

/// HTML page for passkey registration
pub fn register_page(user_id: &str, user_name: &str, rp_id: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register Passkey</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            margin-bottom: 10px;
        }}
        .subtitle {{
            color: #666;
            margin-bottom: 30px;
        }}
        .info {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .info-label {{
            font-weight: bold;
            color: #555;
        }}
        button {{
            background: #28a745;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
            width: 100%;
            margin-top: 20px;
        }}
        button:hover {{
            background: #218838;
        }}
        button:disabled {{
            background: #ccc;
            cursor: not-allowed;
        }}
        .status {{
            margin-top: 20px;
            padding: 15px;
            border-radius: 6px;
            display: none;
        }}
        .status.success {{
            background: #d4edda;
            color: #155724;
            display: block;
        }}
        .status.error {{
            background: #f8d7da;
            color: #721c24;
            display: block;
        }}
        .spinner {{
            border: 3px solid #f3f3f3;
            border-top: 3px solid #28a745;
            border-radius: 50%;
            width: 30px;
            height: 30px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
            display: none;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🔑 Register Passkey</h1>
        <p class="subtitle">Create a new passkey for authentication</p>
        
        <div class="info">
            <div><span class="info-label">User:</span> {user_name}</div>
            <div><span class="info-label">User ID:</span> {user_id}</div>
            <div><span class="info-label">RP ID:</span> {rp_id}</div>
        </div>
        
        <button id="registerButton" onclick="registerPasskey()">
            Create Passkey
        </button>
        
        <div class="spinner" id="spinner"></div>
        <div class="status" id="status"></div>
    </div>

    <script>
        const USER_ID = "{user_id}";
        const USER_NAME = "{user_name}";
        const RP_ID = "{rp_id}";

        function stringToBytes(str) {{
            return new TextEncoder().encode(str);
        }}

        function bytesToBase64(bytes) {{
            return btoa(String.fromCharCode.apply(null, bytes));
        }}

        function showStatus(message, isError = false) {{
            const status = document.getElementById('status');
            status.textContent = message;
            status.className = 'status ' + (isError ? 'error' : 'success');
        }}

        function showSpinner(show) {{
            document.getElementById('spinner').style.display = show ? 'block' : 'none';
            document.getElementById('registerButton').disabled = show;
        }}

        async function registerPasskey() {{
            try {{
                showSpinner(true);
                showStatus('');

                const challenge = new Uint8Array(32);
                crypto.getRandomValues(challenge);

                const credentialCreationOptions = {{
                    publicKey: {{
                        challenge: challenge,
                        rp: {{
                            name: "Stellar Smart Account",
                            id: RP_ID
                        }},
                        user: {{
                            id: stringToBytes(USER_ID),
                            name: USER_NAME,
                            displayName: USER_NAME
                        }},
                        pubKeyCredParams: [
                            {{ alg: -7, type: "public-key" }},   // ES256
                            {{ alg: -257, type: "public-key" }}  // RS256
                        ],
                        authenticatorSelection: {{
                            authenticatorAttachment: "platform",
                            userVerification: "required",
                            residentKey: "required"
                        }},
                        timeout: 60000,
                        attestation: "none"
                    }}
                }};

                console.log('Creating credential...', credentialCreationOptions);
                const credential = await navigator.credentials.create(credentialCreationOptions);
                console.log('Credential created:', credential);

                if (!credential) {{
                    throw new Error('No credential returned');
                }}

                const response = credential.response;
                const result = {{
                    credentialId: bytesToBase64(new Uint8Array(credential.rawId)),
                    attestationObject: bytesToBase64(new Uint8Array(response.attestationObject)),
                    clientDataJSON: bytesToBase64(new Uint8Array(response.clientDataJSON))
                }};

                console.log('Sending result to server:', result);

                const postResponse = await fetch('/register/callback', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify(result)
                }});

                if (postResponse.ok) {{
                    showStatus('✓ Passkey registered successfully! You can close this window.');
                    setTimeout(() => window.close(), 2000);
                }} else {{
                    throw new Error('Failed to send result to server');
                }}

            }} catch (error) {{
                console.error('Error:', error);
                showStatus('Error: ' + error.message, true);
            }} finally {{
                showSpinner(false);
            }}
        }}

        // Auto-start on page load
        window.addEventListener('load', () => {{
            setTimeout(registerPasskey, 500);
        }});
    </script>
</body>
</html>"#,
        user_id = user_id,
        user_name = user_name,
        rp_id = rp_id
    )
}

/// Success page shown after operation completes
pub fn success_page() -> &'static str {
    r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Success</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 40px;
            border-radius: 12px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }
        h1 {
            color: #28a745;
            margin-bottom: 10px;
        }
        p {
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>✓ Success!</h1>
        <p>You can close this window and return to the terminal.</p>
    </div>
    <script>
        setTimeout(() => window.close(), 3000);
    </script>
</body>
</html>"#
}
