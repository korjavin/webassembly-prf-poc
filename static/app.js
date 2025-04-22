// Helper utilities for WebAuthn PRF extension demo
document.addEventListener('DOMContentLoaded', function() {
    // Initialize UI elements
    const addSecretBtn = document.getElementById('addSecretBtn');
    const getPrfBtn = document.getElementById('getPrfBtn');
    const encryptBtn = document.getElementById('encryptBtn');
    const decryptBtn = document.getElementById('decryptBtn');
    const logElement = document.getElementById('log');

    // Disable buttons initially
    getPrfBtn.disabled = true;
    encryptBtn.disabled = true;
    decryptBtn.disabled = true;

    // Store current data
    window.currentData = {
        secret: null,
        secretID: null,
        salt: null,
        prfOutput: null,
        key: null,
        encrypted: false
    };

    // Add event listeners with debugging
    console.log('Setting up event listeners...');
    console.log('addSecretBtn:', addSecretBtn);
    console.log('getPrfBtn:', getPrfBtn);
    console.log('encryptBtn:', encryptBtn);
    console.log('decryptBtn:', decryptBtn);

    if (addSecretBtn) {
        console.log('Adding click listener to addSecretBtn');
        addSecretBtn.addEventListener('click', function() {
            console.log('addSecretBtn clicked');
            addSecret();
        });
    }

    if (getPrfBtn) {
        console.log('Adding click listener to getPrfBtn');
        getPrfBtn.addEventListener('click', function() {
            console.log('getPrfBtn clicked');
            getPrf();
        });
    }

    if (encryptBtn) {
        console.log('Adding click listener to encryptBtn');
        encryptBtn.addEventListener('click', function() {
            console.log('encryptBtn clicked');
            encryptSecret();
        });
    }

    if (decryptBtn) {
        console.log('Adding click listener to decryptBtn');
        decryptBtn.addEventListener('click', function() {
            console.log('decryptBtn clicked');
            decryptSecret();
        });
    }

    // Helper functions for conversion and logging
    window.b64uToBuf = str => {
        const base64 = str.replace(/-/g, '+').replace(/_/g, '/');
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    };

    window.bufToB64u = buf => {
        const bytes = new Uint8Array(buf);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        const base64 = btoa(binary);
        return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    };

    window.bufToHex = buf => {
        return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
    };

    window.log = function(...args) {
        if (logElement) {
            logElement.textContent += args.join(' ') + '\n';
            logElement.scrollTop = logElement.scrollHeight;
        }
        console.log(...args);
    };

    // Initialize WebAssembly
    log('Initializing WebAssembly...');
    const go = new Go();
    WebAssembly.instantiateStreaming(fetch('main.wasm'), go.importObject).then((result) => {
        go.run(result.instance);
        log('WebAssembly initialized successfully');

        // Test WebAssembly functions
        try {
            log('Testing WebAssembly functions...');
            const testBytes = goWasm.generateRandomBytes(16);
            log('Generated random bytes:', testBytes);
            log('WebAssembly functions are working correctly');

            // Enable buttons for testing
            document.getElementById('encryptBtn').disabled = false;
            document.getElementById('decryptBtn').disabled = false;
            log('Enabled encrypt and decrypt buttons for testing');
        } catch (err) {
            log('Error testing WebAssembly functions:', err.message);
            console.error('WebAssembly test error:', err);
        }
    }).catch(err => {
        log('Failed to initialize WebAssembly:', err);
        console.error('WebAssembly initialization error:', err);
    });
});

// Add a new secret
async function addSecret() {
    try {
        log('Generating a new secret...');

        // Generate random secretID (16 bytes) using WebAssembly
        const secretID = goWasm.generateRandomBytes(16);
        log('Generated secretID:', secretID);

        // Generate random salt (32 bytes) using WebAssembly
        const salt = goWasm.generateRandomBytes(32);
        log('Generated salt:', salt);

        // Generate random secret (32 bytes) using WebAssembly
        const secret = goWasm.generateRandomBytes(32);
        log('Generated secret:', secret);

        // Ensure all values are standard base64 (not base64url)
        const standardSecretID = secretID.replace(/-/g, '+').replace(/_/g, '/');
        const standardSalt = salt.replace(/-/g, '+').replace(/_/g, '/');
        const standardSecret = secret.replace(/-/g, '+').replace(/_/g, '/');

        log('Standard base64 secretID:', standardSecretID);
        log('Standard base64 salt:', standardSalt);
        log('Standard base64 secret:', standardSecret);

        // Store the data locally
        window.currentData = {
            secretID,
            salt,
            secret,
            prfOutput: null,
            key: null,
            encrypted: false
        };

        log('Secret generated successfully:');
        log('Secret ID:', secretID);
        log('Salt:', salt);
        log('Secret:', secret);
        log('These values are generated in the browser using WebAssembly.');

        // Enable the getPrfBtn, disable others
        document.getElementById('getPrfBtn').disabled = false;
        document.getElementById('encryptBtn').disabled = true;
        document.getElementById('decryptBtn').disabled = true;

    } catch (error) {
        log('Error adding secret:', error.message);
        console.error('Error adding secret:', error);
    }
}

// Get PRF output
async function getPrf() {
    try {
        if (!window.currentData || !window.currentData.secret) {
            log('No secret available. Please add a secret first.');
            return;
        }

        log('Getting PRF output for secret ID:', window.currentData.secretID);

        // Step 1: Create WebAuthn options with PRF extension
        log('Step 1: Creating WebAuthn options with PRF extension...');

        // Create a random challenge
        const challenge = new Uint8Array(32);
        window.crypto.getRandomValues(challenge);

        // Create WebAuthn options
        const options = {
            publicKey: {
                challenge: challenge,
                rpId: window.location.hostname,
                userVerification: 'preferred',
                extensions: {
                    prf: {
                        eval: {
                            first: b64uToBuf(window.currentData.salt)
                        }
                    }
                }
            }
        };

        log('Created WebAuthn options:');
        log(JSON.stringify({
            publicKey: {
                ...options.publicKey,
                challenge: 'ArrayBuffer (base64): ' + bufToB64u(options.publicKey.challenge),
                extensions: options.publicKey.extensions ? {
                    prf: options.publicKey.extensions.prf ? {
                        eval: options.publicKey.extensions.prf.eval ? {
                            first: 'ArrayBuffer (base64): ' + window.currentData.salt
                        } : undefined
                    } : undefined
                } : undefined
            }
        }, null, 2));

        // Step 2: Call navigator.credentials.get()
        log('Step 2: Calling navigator.credentials.get() with PRF extension...');
        log('This will prompt the authenticator to evaluate the PRF with the provided salt.');

        const credential = await navigator.credentials.get(options);

        log('Authenticator response received!');
        log('Response type: ' + credential.type);
        log('Credential ID: ' + credential.id);
        log('Raw ID (base64): ' + bufToB64u(credential.rawId));

        // Step 3: Extract PRF result
        log('Step 3: Extracting PRF result from authenticator response...');

        // Extract and explain the client extension results
        const clientExtResults = credential.getClientExtensionResults();
        log('Client extension results:');
        log(JSON.stringify(clientExtResults, null, 2));

        if (!clientExtResults.prf || !clientExtResults.prf.results || !clientExtResults.prf.results.first) {
            throw new Error('PRF extension result not found in authenticator response');
        }

        const prfResult = clientExtResults.prf.results.first;
        log('PRF output details:');
        log('- Hex format: ' + bufToHex(prfResult));
        log('- Base64 format: ' + btoa(String.fromCharCode(...new Uint8Array(prfResult))));
        log('- Length: ' + prfResult.byteLength + ' bytes');

        // Step 4: Derive key from PRF output
        log('Step 4: Deriving encryption key from PRF output using Argon2id...');

        // Convert ArrayBuffer to standard base64
        const prfBase64 = btoa(String.fromCharCode(...new Uint8Array(prfResult)));
        log('PRF output (standard base64):', prfBase64);

        // Make sure it's properly padded
        const paddedPrfBase64 = prfBase64.padEnd(Math.ceil(prfBase64.length / 4) * 4, '=');
        log('PRF output (padded base64):', paddedPrfBase64);

        // Derive key using WebAssembly
        const key = goWasm.deriveKeyFromPRF(paddedPrfBase64);
        log('Derived key (base64):', key);

        // Store the PRF output and key
        window.currentData.prfOutput = prfBase64;
        window.currentData.key = key;

        // Enable the encrypt button
        document.getElementById('encryptBtn').disabled = false;

        log('');
        log('PRF output and key derived successfully.');
        log('You can now encrypt the secret by clicking the "Encrypt Secret" button.');

    } catch (error) {
        log('Error getting PRF output:', error.message);
        console.error('Error getting PRF output:', error);
    }
}

// Encrypt secret
async function encryptSecret() {
    console.log('encryptSecret function called');
    log('encryptSecret function called');
    try {
        if (!window.currentData || !window.currentData.key) {
            log('No key available. Please get PRF output first.');
            return;
        }

        log('Encrypting secret...');

        // Step 1: Encrypt the secret using AES-256-GCM
        log('Step 1: Encrypting the secret using AES-256-GCM...');
        log('Key:', window.currentData.key);
        log('Secret:', window.currentData.secret);

        try {
            // Convert secret to standard base64 (not base64url)
            // First, convert base64url to standard base64 by replacing - with + and _ with /
            const secretBase64 = window.currentData.secret.replace(/-/g, '+').replace(/_/g, '/');
            // Add padding if needed
            const paddedSecretBase64 = secretBase64.padEnd(Math.ceil(secretBase64.length / 4) * 4, '=');

            log('Secret (standard base64):', paddedSecretBase64);

            // Call the WebAssembly function
            const encryptionResult = goWasm.encryptSecret(window.currentData.key, paddedSecretBase64);
            console.log('Raw encryption result:', encryptionResult);

            // Check if the result is valid
            if (!encryptionResult || typeof encryptionResult !== 'object') {
                throw new Error('Invalid encryption result: ' + JSON.stringify(encryptionResult));
            }

            // Access properties safely
            const ciphertext = encryptionResult.ciphertext || '';
            const nonce = encryptionResult.nonce || '';
            const aad = encryptionResult.aad || '';

            if (!ciphertext || !nonce || !aad) {
                throw new Error('Missing required encryption properties');
            }

            log('Encryption result:');
            log('- Ciphertext (base64):', ciphertext);
            log('- Nonce (base64):', nonce);
            log('- AAD (base64):', aad);

            // Store the encryption result for later use
            window.currentData.encryptionResult = {
                ciphertext: ciphertext,
                nonce: nonce,
                aad: aad
            };
        } catch (err) {
            log('Error during encryption:', err.message);
            console.error('Encryption error:', err);
            throw err;
        }

        // Step 2: Send encrypted data to server
        log('Step 2: Sending encrypted data to server...');
        const storeResponse = await fetch('/api/secret/store', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                secretID: window.currentData.secretID,
                salt: window.currentData.salt,
                ciphertext: window.currentData.encryptionResult.ciphertext,
                nonce: window.currentData.encryptionResult.nonce,
                aad: window.currentData.encryptionResult.aad
            })
        });

        if (!storeResponse.ok) {
            const errorText = await storeResponse.text();
            throw new Error(`Failed to store encrypted data: ${errorText}`);
        }

        const storeResult = await storeResponse.json();
        log('Server response:', JSON.stringify(storeResult, null, 2));
        log('Encrypted data stored successfully on the server.');

        // Update state
        window.currentData.encrypted = true;

        // Enable decrypt button
        document.getElementById('decryptBtn').disabled = false;

        log('');
        log('Secret encrypted and stored successfully.');
        log('You can now decrypt the secret by clicking the "Decrypt Secret" button.');

    } catch (error) {
        log('Error encrypting secret:', error.message);
        console.error('Error encrypting secret:', error);
    }
}

// Decrypt secret
async function decryptSecret() {
    console.log('decryptSecret function called');
    log('decryptSecret function called');
    try {
        if (!window.currentData || !window.currentData.key || !window.currentData.encrypted) {
            log('No encrypted data available. Please encrypt a secret first.');
            return;
        }

        log('Decrypting secret...');

        // Step 1: Retrieve encrypted data from server
        log('Step 1: Retrieving encrypted data from server...');

        const retrieveResponse = await fetch('/api/secret/retrieve', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                secretID: window.currentData.secretID
            })
        });

        if (!retrieveResponse.ok) {
            const errorText = await retrieveResponse.text();
            throw new Error(`Failed to retrieve encrypted data: ${errorText}`);
        }

        const retrieveResult = await retrieveResponse.json();
        log('Retrieved encrypted data:');
        log('- Secret ID:', retrieveResult.secretID);
        log('- Salt:', retrieveResult.salt);
        log('- Ciphertext:', retrieveResult.ciphertext);
        log('- Nonce:', retrieveResult.nonce);
        log('- AAD:', retrieveResult.aad);

        // Step 2: Decrypt the secret
        log('Step 2: Decrypting the secret...');

        // Make sure all values are properly padded standard base64
        const paddedCiphertext = retrieveResult.ciphertext.padEnd(Math.ceil(retrieveResult.ciphertext.length / 4) * 4, '=');
        const paddedNonce = retrieveResult.nonce.padEnd(Math.ceil(retrieveResult.nonce.length / 4) * 4, '=');
        const paddedAAD = retrieveResult.aad.padEnd(Math.ceil(retrieveResult.aad.length / 4) * 4, '=');

        log('Padded ciphertext:', paddedCiphertext);
        log('Padded nonce:', paddedNonce);
        log('Padded AAD:', paddedAAD);

        const decryptedSecret = goWasm.decryptSecret(
            window.currentData.key,
            paddedCiphertext,
            paddedNonce,
            paddedAAD
        );
        log('Decryption result:');
        log('- Decrypted secret (base64):', decryptedSecret);
        log('- Original secret (base64):', window.currentData.secret);

        // Verify the decryption
        // Convert the decrypted secret from standard base64 to base64url for comparison
        const decryptedSecretB64Url = decryptedSecret.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
        log('Decrypted secret (base64url):', decryptedSecretB64Url);

        if (decryptedSecretB64Url === window.currentData.secret) {
            log('Decryption successful! The decrypted secret matches the original secret.');
        } else {
            log('Warning: The decrypted secret does not match the original secret.');
            log('This could be due to differences in base64 encoding formats.');

            // Try comparing the decoded values
            try {
                const originalBytes = atob(window.currentData.secret.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(window.currentData.secret.length / 4) * 4, '='));
                const decryptedBytes = atob(decryptedSecret.padEnd(Math.ceil(decryptedSecret.length / 4) * 4, '='));

                if (originalBytes === decryptedBytes) {
                    log('However, the decoded binary values match! The decryption is actually successful.');
                } else {
                    log('The decoded binary values also do not match. There might be an actual decryption issue.');
                }
            } catch (e) {
                log('Error comparing decoded values:', e.message);
            }
        }

        log('');
        log('Security and Cryptographic Properties:');
        log('1. Deterministic: The same credential and salt will always produce the same PRF output');
        log('2. Credential-specific: Different credentials produce different outputs for the same salt');
        log('3. Salt-specific: Different salts produce different outputs for the same credential');
        log('4. High-entropy: The 32-byte output has 256 bits of entropy, suitable for cryptographic keys');
        log('5. Server-blind: The server never sees the private key or the encryption key, only the encrypted data');

    } catch (error) {
        log('Error decrypting secret:', error.message);
        console.error('Error decrypting secret:', error);
    }
}
