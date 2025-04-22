package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"syscall/js"

	"golang.org/x/crypto/argon2"
)

// deriveKeyFromPRF derives a key from the PRF output using Argon2id
func deriveKeyFromPRF(this js.Value, args []js.Value) interface{} {
	if len(args) < 1 {
		return js.Error{Value: js.ValueOf("Missing PRF output argument")}
	}

	// Decode PRF output from base64
	prfOutputBase64 := args[0].String()
	prfOutput, err := base64.StdEncoding.DecodeString(prfOutputBase64)
	if err != nil {
		return js.Error{Value: js.ValueOf("Invalid PRF output: " + err.Error())}
	}

	// Use Argon2id to derive a key
	// Parameters: time=1, memory=64*1024, threads=4, keyLen=32
	key := argon2.IDKey(prfOutput, nil, 1, 64*1024, 4, 32)

	// Return base64 encoded key
	return base64.StdEncoding.EncodeToString(key)
}

// encryptSecret encrypts a secret using AES-256-GCM
func encryptSecret(this js.Value, args []js.Value) interface{} {
	if len(args) < 2 {
		return js.Error{Value: js.ValueOf("Missing arguments: key, secret")}
	}

	// Decode key from base64
	keyBase64 := args[0].String()
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return js.Error{Value: js.ValueOf("Invalid key: " + err.Error())}
	}

	// Decode secret from base64
	secretBase64 := args[1].String()
	secret, err := base64.StdEncoding.DecodeString(secretBase64)
	if err != nil {
		return js.Error{Value: js.ValueOf("Invalid secret: " + err.Error())}
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return js.Error{Value: js.ValueOf("AES cipher creation failed: " + err.Error())}
	}

	// Create GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return js.Error{Value: js.ValueOf("GCM mode creation failed: " + err.Error())}
	}

	// Create nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return js.Error{Value: js.ValueOf("Nonce generation failed: " + err.Error())}
	}

	// Fixed AAD (16 bytes)
	aad := []byte("WebAuthnPRFDemo!")

	// Encrypt
	ciphertext := aesGCM.Seal(nil, nonce, secret, aad)

	// Return JSON with base64 encoded values
	result := map[string]interface{}{
		"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
		"nonce":      base64.StdEncoding.EncodeToString(nonce),
		"aad":        base64.StdEncoding.EncodeToString(aad),
	}

	// Convert result to JS object
	jsResult := js.ValueOf(map[string]interface{}{})
	for k, v := range result {
		jsResult.Set(k, js.ValueOf(v))
	}

	return jsResult
}

// decryptSecret decrypts a secret using AES-256-GCM
func decryptSecret(this js.Value, args []js.Value) interface{} {
	if len(args) < 4 {
		return js.Error{Value: js.ValueOf("Missing arguments: key, ciphertext, nonce, aad")}
	}

	// Decode key from base64
	keyBase64 := args[0].String()
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return js.Error{Value: js.ValueOf("Invalid key: " + err.Error())}
	}

	// Decode ciphertext from base64
	ciphertextBase64 := args[1].String()
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return js.Error{Value: js.ValueOf("Invalid ciphertext: " + err.Error())}
	}

	// Decode nonce from base64
	nonceBase64 := args[2].String()
	nonce, err := base64.StdEncoding.DecodeString(nonceBase64)
	if err != nil {
		return js.Error{Value: js.ValueOf("Invalid nonce: " + err.Error())}
	}

	// Decode AAD from base64
	aadBase64 := args[3].String()
	aad, err := base64.StdEncoding.DecodeString(aadBase64)
	if err != nil {
		return js.Error{Value: js.ValueOf("Invalid AAD: " + err.Error())}
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return js.Error{Value: js.ValueOf("AES cipher creation failed: " + err.Error())}
	}

	// Create GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return js.Error{Value: js.ValueOf("GCM mode creation failed: " + err.Error())}
	}

	// Decrypt
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return js.Error{Value: js.ValueOf("Decryption failed: " + err.Error())}
	}

	// Return base64 encoded plaintext
	return base64.StdEncoding.EncodeToString(plaintext)
}
