// Helper utilities for WebAuthn PRF extension demo
// Global variables for UI elements
let getPrfBtn;
let encryptBtn;
let decryptBtn;
let newSecretBtn;
let loadSecretsBtn;
let secretsList;
let logElement;

// Global variables for form fields
let secretIDInput;
let saltInput;
let secretInput;
let keyInput;
let ciphertextInput;
let nonceInput;
let aadInput;

document.addEventListener('DOMContentLoaded', function() {
    // Initialize UI elements
    getPrfBtn = document.getElementById('getPrfBtn');
    encryptBtn = document.getElementById('encryptBtn');
    decryptBtn = document.getElementById('decryptBtn');
    newSecretBtn = document.getElementById('newSecretBtn');
    loadSecretsBtn = document.getElementById('loadSecretsBtn');
    secretsList = document.getElementById('secretsList');
    logElement = document.getElementById('log');

    // Form fields
    secretIDInput = document.getElementById('secretID');
    saltInput = document.getElementById('salt');
    secretInput = document.getElementById('secret');
    keyInput = document.getElementById('key');
    ciphertextInput = document.getElementById('ciphertext');
    nonceInput = document.getElementById('nonce');
    aadInput = document.getElementById('aad');

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
        encrypted: false,
        secrets: []
    };

    // Add event listeners with debugging
    console.log('Setting up event listeners...');

    if (getPrfBtn) {
        getPrfBtn.addEventListener('click', function() {
            console.log('getPrfBtn clicked');
            getPrf();
        });
    }

    if (encryptBtn) {
        encryptBtn.addEventListener('click', function() {
            console.log('encryptBtn clicked');
            encryptSecret();
        });
    }

    if (decryptBtn) {
        decryptBtn.addEventListener('click', function() {
            console.log('decryptBtn clicked');
            decryptSecret();
        });
    }

    if (newSecretBtn) {
        newSecretBtn.addEventListener('click', function() {
            console.log('newSecretBtn clicked');
            generateNewSecret();
        });
    }

    if (loadSecretsBtn) {
        loadSecretsBtn.addEventListener('click', function() {
            console.log('loadSecretsBtn clicked');
            loadSecrets();
        });
    }

    // Add event listeners for form fields to update currentData
    secretIDInput.addEventListener('input', function() {
        window.currentData.secretID = this.value;
    });

    saltInput.addEventListener('input', function() {
        window.currentData.salt = this.value;
    });

    secretInput.addEventListener('input', function() {
        window.currentData.secret = this.value;
    });

    keyInput.addEventListener('input', function() {
        window.currentData.key = this.value;
    });

    ciphertextInput.addEventListener('input', function() {
        if (!window.currentData.encryptionResult) {
            window.currentData.encryptionResult = {};
        }
        window.currentData.encryptionResult.ciphertext = this.value;
    });

    nonceInput.addEventListener('input', function() {
        if (!window.currentData.encryptionResult) {
            window.currentData.encryptionResult = {};
        }
        window.currentData.encryptionResult.nonce = this.value;
    });

    aadInput.addEventListener('input', function() {
        if (!window.currentData.encryptionResult) {
            window.currentData.encryptionResult = {};
        }
        window.currentData.encryptionResult.aad = this.value;
    });

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

// Global log function
window.log = function(...args) {
    if (logElement) {
        logElement.textContent += args.join(' ') + '\n';
        logElement.scrollTop = logElement.scrollHeight;
    }
    console.log(...args);
};

// Helper functions for text encoding/decoding
function textToBase64(text) {
    // Convert text to base64
    const base64 = btoa(text);
    // Convert to base64url format
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function base64ToText(base64) {
    try {
        // Convert from base64url to standard base64
        const standardBase64 = base64.replace(/-/g, '+').replace(/_/g, '/');
        // Add padding if needed
        const paddedBase64 = standardBase64.padEnd(Math.ceil(standardBase64.length / 4) * 4, '=');
        // Decode base64 to text
        return atob(paddedBase64);
    } catch (e) {
        console.error('Error decoding base64:', e);
        return base64; // Return original if decoding fails
    }
}

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

        // Generate random secret (32 bytes) using WebAssembly and convert to text
        const secretBase64 = goWasm.generateRandomBytes(32);
        // For demo purposes, we'll use a simple text secret instead of the random bytes
        const secretText = 'This is a secret message that will be encrypted';
        log('Generated secret (text):', secretText);
        log('Secret as base64url:', textToBase64(secretText));

        // Ensure all values are standard base64 (not base64url)
        const standardSecretID = secretID.replace(/-/g, '+').replace(/_/g, '/');
        const standardSalt = salt.replace(/-/g, '+').replace(/_/g, '/');

        log('Standard base64 secretID:', standardSecretID);
        log('Standard base64 salt:', standardSalt);

        // Set a default AAD (Additional Authenticated Data)
        const aadText = 'WebAuthnPRFDemo!';
        log('Default AAD (text):', aadText);
        log('AAD as base64url:', textToBase64(aadText));

        // Store the data locally
        window.currentData = {
            secretID,
            salt,
            secret: textToBase64(secretText),  // Store base64 version for encryption
            secretText: secretText,           // Store text version for display
            aad: textToBase64(aadText),       // Store base64 version for encryption
            aadText: aadText,                 // Store text version for display
            prfOutput: null,
            key: null,
            encrypted: false,
            secrets: window.currentData ? window.currentData.secrets : []
        };

        // Update form fields
        secretIDInput.value = secretID;
        saltInput.value = salt;
        secretInput.value = secretText;  // Display as plain text
        keyInput.value = '';
        ciphertextInput.value = '';
        nonceInput.value = '';
        aadInput.value = aadText;  // Display as plain text

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

// Function to generate a new secret (same as addSecret but with a different name for clarity)
async function generateNewSecret() {
    await addSecret();
}

// Function to load secrets from the server
async function loadSecrets() {
    try {
        log('Loading secrets from server...');

        const response = await fetch('/api/secret/list', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to load secrets: ${errorText}`);
        }

        const result = await response.json();
        log('Retrieved secrets:', JSON.stringify(result, null, 2));

        // Store the secrets
        window.currentData.secrets = result.secrets || [];

        // Clear the secrets list
        secretsList.innerHTML = '';

        // Add each secret to the list
        if (window.currentData.secrets.length === 0) {
            secretsList.innerHTML = '<div class="log-entry">No secrets found</div>';
        } else {
            window.currentData.secrets.forEach((secret, index) => {
                const secretItem = document.createElement('div');
                secretItem.className = 'log-entry';
                secretItem.innerHTML = `<strong>Secret ${index + 1}:</strong> ID=${secret.secretID} <button class="load-secret-btn" data-index="${index}">Load</button>`;
                secretsList.appendChild(secretItem);
            });

            // Add event listeners to load buttons
            document.querySelectorAll('.load-secret-btn').forEach(button => {
                button.addEventListener('click', function() {
                    const index = parseInt(this.getAttribute('data-index'));
                    loadSecretDetails(index);
                });
            });
        }

        log('Secrets loaded successfully');
    } catch (error) {
        log('Error loading secrets:', error.message);
        console.error('Error loading secrets:', error);
    }
}

// Function to load a specific secret's details
function loadSecretDetails(index) {
    try {
        const secret = window.currentData.secrets[index];
        if (!secret) {
            throw new Error('Secret not found');
        }

        log(`Loading secret details for index ${index}:`, JSON.stringify(secret, null, 2));

        // Try to decode AAD from base64 to text
        let aadText = '';
        try {
            aadText = base64ToText(secret.aad);
            log('Decoded AAD text:', aadText);
        } catch (e) {
            log('Could not decode AAD as text, using base64 value');
            aadText = secret.aad;
        }

        // Update form fields
        secretIDInput.value = secret.secretID;
        saltInput.value = secret.salt;
        ciphertextInput.value = secret.ciphertext;
        nonceInput.value = secret.nonce;
        aadInput.value = aadText;  // Display as text if possible

        // Update currentData
        window.currentData.secretID = secret.secretID;
        window.currentData.salt = secret.salt;
        // Set a placeholder for the secret - it will be populated after decryption
        window.currentData.secret = 'placeholder-will-be-decrypted';
        window.currentData.aad = secret.aad;  // Store base64 version
        window.currentData.aadText = aadText; // Store text version
        window.currentData.encryptionResult = {
            ciphertext: secret.ciphertext,
            nonce: secret.nonce,
            aad: secret.aad
        };
        window.currentData.encrypted = true;

        // Enable buttons
        getPrfBtn.disabled = false;
        decryptBtn.disabled = false;

        log('Secret details loaded successfully');
    } catch (error) {
        log('Error loading secret details:', error.message);
        console.error('Error loading secret details:', error);
    }
}

// Get PRF output
async function getPrf() {
    try {
        if (!window.currentData || !window.currentData.salt) {
            log('No salt available. Please add a secret or load one first.');
            return;
        }

        // If we're using a loaded secret, we don't need to check for the secret property
        // as it will be populated after decryption
        if (!window.currentData.encrypted && !window.currentData.secret) {
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

        // Update form fields
        keyInput.value = key;

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
            // Get the current secret text from the input field
            const currentSecretText = secretInput.value;
            // Convert to base64url for encryption
            const secretBase64url = textToBase64(currentSecretText);
            // Update the currentData with the new secret
            window.currentData.secret = secretBase64url;
            window.currentData.secretText = currentSecretText;

            // Get the current AAD text from the input field
            const currentAadText = aadInput.value;
            // Convert to base64url for encryption
            const aadBase64url = textToBase64(currentAadText);
            // Update the currentData with the new AAD
            window.currentData.aad = aadBase64url;
            window.currentData.aadText = currentAadText;

            // Convert secret to standard base64 (not base64url)
            const secretBase64 = secretBase64url.replace(/-/g, '+').replace(/_/g, '/');
            // Add padding if needed
            const paddedSecretBase64 = secretBase64.padEnd(Math.ceil(secretBase64.length / 4) * 4, '=');

            log('Secret text:', currentSecretText);
            log('Secret (base64url):', secretBase64url);
            log('Secret (standard base64):', paddedSecretBase64);
            log('AAD text:', currentAadText);
            log('AAD (base64url):', aadBase64url);

            // Get the AAD value
            const aadBase64 = aadBase64url.replace(/-/g, '+').replace(/_/g, '/');
            // Add padding if needed
            const paddedAadBase64 = aadBase64.padEnd(Math.ceil(aadBase64.length / 4) * 4, '=');
            log('AAD (standard base64):', paddedAadBase64);

            // Call the WebAssembly function with the AAD as the third argument
            const encryptionResult = goWasm.encryptSecret(window.currentData.key, paddedSecretBase64, paddedAadBase64);
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

            // Update form fields
            ciphertextInput.value = ciphertext;
            nonceInput.value = nonce;
            aadInput.value = aad;
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

        // Step 1: Check if we need to retrieve data from server or use form fields
        let retrieveResult;

        // If the form fields are filled, use them
        if (ciphertextInput.value && nonceInput.value && aadInput.value) {
            log('Step 1: Using form field values for decryption...');

            // Convert AAD from text to base64 if needed
            const aadText = aadInput.value;
            let aadBase64 = aadInput.value;

            // Check if the AAD is already in base64 format
            try {
                // Try to decode it as base64
                atob(aadBase64.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(aadBase64.length / 4) * 4, '='));
                log('AAD is already in base64 format');
            } catch (e) {
                // If it fails, it's probably text that needs to be encoded
                aadBase64 = textToBase64(aadText);
                log('Converted AAD from text to base64:', aadBase64);
            }

            retrieveResult = {
                secretID: secretIDInput.value,
                salt: saltInput.value,
                ciphertext: ciphertextInput.value,
                nonce: nonceInput.value,
                aad: aadBase64
            };
            log('Using encrypted data from form fields:');
        } else {
            // Otherwise retrieve from server
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

            retrieveResult = await retrieveResponse.json();
            log('Retrieved encrypted data from server:');

            // Update form fields with retrieved data
            secretIDInput.value = retrieveResult.secretID;
            saltInput.value = retrieveResult.salt;
            ciphertextInput.value = retrieveResult.ciphertext;
            nonceInput.value = retrieveResult.nonce;
            aadInput.value = retrieveResult.aad;
        }

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

        try {
            const decryptedSecret = goWasm.decryptSecret(
                window.currentData.key,
                paddedCiphertext,
                paddedNonce,
                paddedAAD
            );

            // Check if decryption was successful
            if (!decryptedSecret) {
                throw new Error('Decryption failed - authentication tag mismatch');
            }

            log('Decryption result:');
            log('- Decrypted secret (base64):', decryptedSecret);
            log('- Original secret (base64):', window.currentData.secret);

            // Convert the decrypted secret from base64 to text
            const decryptedSecretB64Url = decryptedSecret.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
            const decryptedText = base64ToText(decryptedSecretB64Url);

            // Update the secret input field with the decrypted text
            secretInput.value = decryptedText;
            window.currentData.secret = decryptedSecretB64Url;
            window.currentData.secretText = decryptedText;

            log('Decrypted secret (text):', decryptedText);

            // Verify the decryption
            log('Decrypted secret (base64url):', decryptedSecretB64Url);

            // If we're decrypting a loaded secret, we don't have the original to compare
            if (window.currentData.secret === 'placeholder-will-be-decrypted') {
                log('Decryption successful! This was a loaded secret, so we have no original to compare.');
                // Update the secret with the decrypted value
                window.currentData.secret = decryptedSecretB64Url;
            } else if (decryptedSecretB64Url === window.currentData.secret) {
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
        } catch (error) {
            log('Decryption failed:', error.message);
            log('This is expected if you changed the AAD value after encryption.');
            log('For AES-GCM, the AAD is part of the authentication tag calculation.');
            log('If the AAD changes, the authentication will fail even if the key and nonce are correct.');
            throw error; // Re-throw to be caught by the outer try-catch
        }

        // All decryption logic is now handled inside the try-catch block

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
