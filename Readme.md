# WebAuthn PRF Extension Demo with Browser-Side Cryptography

A comprehensive, self-contained web application that demonstrates **how to use the WebAuthn PRF (Pseudo-Random Function) extension to derive a deterministic 32-byte secret from a passkey and an application-chosen salt**. The goal is strictly educational: the app shows every request, response, and cryptographic value involved so developers can see exactly **how the PRF extension produces a stable output that can later feed a KDF to wrap a DEK (Data Encryption Key)**.

## Key Features

- **Browser-Side Cryptography**: All cryptographic operations are performed in the browser using WebAssembly (Go compiled to WASM)
- **Persistent Storage**: User registrations and encrypted secrets are stored in a data.json file
- **Interactive UI**: Edit secret attributes directly in the UI for educational purposes
- **Detailed Logging**: Every step of the process is logged for transparency and learning

The application supports the following flows:

1. **Register/Login with Passkeys**: Create and use WebAuthn credentials (implemented in `passkey.go`)
2. **New Secret**: Generate a random *secret ID*, *salt*, and *secret* on the client
3. **Get PRF Output**: Ask the authenticator to evaluate the PRF extension with the salt; returns a deterministic 32-byte blob
4. **Encrypt/Decrypt**: Use the PRF output to derive an encryption key and encrypt/decrypt the secret
5. **Load Secrets**: Retrieve previously stored encrypted secrets

---

## What We Are Demonstrating

| Topic | Why it matters |
|-------|----------------|
| **WebAuthn PRF extension** | Allows web clients to ask an authenticator to compute an HMAC-like function keyed by the private credential key. Output never leaves the authenticator unprotected and is calculable only with user presence. |
| **Deterministic key output** | Given *the same credential* and *the same salt*, the PRF returns **exactly the same 32 bytes every time**, making it perfect for envelope-encryption KEKs. |
| **Salt = domain separation** | The application chooses an arbitrary 32-byte salt (random). Different salts produce different outputs, allowing multiple independent keys from one credential. |
| **Transparent step-by-step UX** | Each stage (generated salt, JS request JSON, authenticator response, PRF result) is printed to the screen so learners can follow the flow. |
| **Interactive experimentation** | Users can edit AAD and other parameters to see how they affect encryption/decryption, providing hands-on learning about authenticated encryption. |

We deliberately focus on the core functionality of **"passkey → PRF → deterministic secret → encryption/decryption"** while providing a user-friendly interface for experimentation.

---

## High-Level Flow

1. **Register**: User creates a passkey for the demo site.
2. **Login**: User authenticates with their passkey.
3. **New Secret**:
   1. Browser generates:
      * `secretID` – 16 random bytes (base64url-encoded).
      * `salt` – 32 random bytes (base64url-encoded).
      * `secret` – Random text that will be encrypted.
   2. Browser stores these values in memory and displays them in the UI.
4. **Get PRF Output**:
   1. Browser builds a WebAuthn assertion options object with the PRF extension.
   2. Browser runs `navigator.credentials.get({publicKey: options})`.
   3. Authenticator verifies user presence, computes the PRF output, and returns a 32-byte result.
   4. Browser uses Argon2id to derive a 256-bit key from the PRF output.
5. **Encrypt Secret**:
   1. Browser uses AES-256-GCM and the derived key to encrypt the secret.
   2. Browser uses the AAD (Additional Authenticated Data) to prevent tampering.
   3. Browser sends the encrypted secret, nonce (IV), AAD, salt, and secretID to the server.
   4. Server stores the encrypted data in the data.json file.
6. **Decrypt Secret**:
   1. Browser retrieves the encrypted data from the server.
   2. Browser repeats the PRF and key derivation process with the same secretID and salt.
   3. Browser decrypts the secret using the derived key, nonce, and AAD.
   4. The decrypted secret is displayed in the UI.

---

## Implementation Details

For all cryptographic operations on the browser side (key derivation, encryption, and decryption), we use [WebAssembly](https://webassembly.org/) compiled from Go code. This allows us to use Go's robust cryptographic libraries directly in the browser.

The server side is implemented in Go and focuses on storing and retrieving data. It doesn't perform any cryptographic operations, ensuring that sensitive operations remain client-side.

### Key Components:

- **WebAssembly Module**: Handles cryptographic operations (wasm/crypto.go)
- **Passkey Authentication**: Manages WebAuthn registration and login (passkey.go)
- **Secret Management**: Handles storage and retrieval of encrypted secrets (secret.go)
- **Persistence Layer**: Saves and loads data to/from data.json (persistence.go)
- **Interactive UI**: Allows users to view and edit secret attributes (static/app.js, static/index.html)

## Running the Demo

```bash
# Requires Go 1.22+
$ git clone https://github.com/yourusername/webassembly-prf-poc
$ cd webassembly-prf-poc
$ go build
$ ./webassembly-prf-poc
# Open http://localhost:8084 in Chrome ≥119 or Edge ≥119 (PRF enabled)
```

> ⚠️ As of April 2025, the PRF extension is supported in Chromium-based browsers with platform authenticators and recent external security keys (YubiKey Bio 5C NFC, Titan M, etc.). Safari/Firefox may require nightly builds.

---

## Glossary

- **secretID**: Opaque 16-byte identifier for one logical "secret". Used as the `id` field in the PRF extension.
- **salt**: 32-byte random value generated by the browser; unique per secret, guarantees domain separation.
- **secret**: Random text that will be encrypted and decrypted.
- **PRF output**: 32-byte deterministic result, cryptographically bound to `(credential ID, salt)`.
- **AAD**: Additional Authenticated Data used in AES-GCM to prevent tampering.
- **nonce**: Initialization Vector (IV) used in AES-GCM encryption.
- **KEK**: Key Encryption Key derived from the PRF output.
- **DEK**: Data Encryption Key, the secret being protected.

---

## Security Considerations

This demo is for educational purposes only and should not be used in production without additional security measures:

1. **Error Handling**: The demo includes basic error handling but may not cover all edge cases.
2. **Key Management**: In a production environment, consider additional key management strategies.
3. **Backup and Recovery**: Implement proper backup and recovery mechanisms for keys and data.
4. **Rate Limiting**: Add rate limiting to prevent brute force attacks.
5. **Audit Logging**: Implement comprehensive audit logging for security events.

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
