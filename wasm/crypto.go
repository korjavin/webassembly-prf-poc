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
	js.Global().Get("console").Call("log", "deriveKeyFromPRF called with args length:", len(args))

	if len(args) < 1 {
		return js.Error{Value: js.ValueOf("Missing PRF output argument")}
	}

	// Decode PRF output from base64
	prfOutputBase64 := args[0].String()
	js.Global().Get("console").Call("log", "PRF output base64 length:", len(prfOutputBase64))
	js.Global().Get("console").Call("log", "PRF output base64 value:", prfOutputBase64)
	prfOutput, err := safeDecodeBase64(prfOutputBase64)
	if err != nil {
		js.Global().Get("console").Call("log", "PRF output decode error:", err.Error())
		return js.Error{Value: js.ValueOf("Invalid PRF output: " + err.Error())}
	}

	// Use Argon2id to derive a key
	// Parameters: time=1, memory=64*1024, threads=4, keyLen=32
	key := argon2.IDKey(prfOutput, nil, 1, 64*1024, 4, 32)

	// Return base64 encoded key
	keyBase64 := base64.StdEncoding.EncodeToString(key)
	js.Global().Get("console").Call("log", "Derived key base64:", keyBase64)
	return keyBase64
}

// safeDecodeBase64 attempts to decode a base64 string, handling URL encoding and padding
func safeDecodeBase64(input string) ([]byte, error) {
	// Try standard base64 first
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err == nil {
		return decoded, nil
	}

	// Try URL-safe base64
	decoded, err = base64.URLEncoding.DecodeString(input)
	if err == nil {
		return decoded, nil
	}

	// Try URL-safe base64 without padding
	decoded, err = base64.RawURLEncoding.DecodeString(input)
	if err == nil {
		return decoded, nil
	}

	// Try standard base64 without padding
	decoded, err = base64.RawStdEncoding.DecodeString(input)
	if err == nil {
		return decoded, nil
	}

	// If all attempts fail, return the last error
	return nil, err
}

// encryptSecret encrypts a secret using AES-256-GCM
func encryptSecret(this js.Value, args []js.Value) interface{} {
	js.Global().Get("console").Call("log", "encryptSecret called with args length:", len(args))

	if len(args) < 2 {
		return js.Error{Value: js.ValueOf("Missing arguments: key, secret")}
	}

	// Decode key from base64
	keyBase64 := args[0].String()
	js.Global().Get("console").Call("log", "Key base64 length:", len(keyBase64))
	key, err := safeDecodeBase64(keyBase64)
	if err != nil {
		js.Global().Get("console").Call("log", "Key decode error:", err.Error())
		return js.Error{Value: js.ValueOf("Invalid key: " + err.Error())}
	}

	// Decode secret from base64
	secretBase64 := args[1].String()
	js.Global().Get("console").Call("log", "Secret base64 length:", len(secretBase64))
	js.Global().Get("console").Call("log", "Secret base64 value:", secretBase64)
	secret, err := safeDecodeBase64(secretBase64)
	if err != nil {
		js.Global().Get("console").Call("log", "Secret decode error:", err.Error())
		return js.Error{Value: js.ValueOf("Invalid secret: " + err.Error())}
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		js.Global().Get("console").Call("log", "AES cipher error:", err.Error())
		return js.Error{Value: js.ValueOf("AES cipher creation failed: " + err.Error())}
	}

	// Create GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		js.Global().Get("console").Call("log", "GCM mode error:", err.Error())
		return js.Error{Value: js.ValueOf("GCM mode creation failed: " + err.Error())}
	}

	// Create nonce
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		js.Global().Get("console").Call("log", "Nonce generation error:", err.Error())
		return js.Error{Value: js.ValueOf("Nonce generation failed: " + err.Error())}
	}

	// Fixed AAD (16 bytes)
	aad := []byte("WebAuthnPRFDemo!")

	// Encrypt
	ciphertext := aesGCM.Seal(nil, nonce, secret, aad)

	// Convert to base64 strings
	ciphertextBase64 := base64.StdEncoding.EncodeToString(ciphertext)
	nonceBase64 := base64.StdEncoding.EncodeToString(nonce)
	aadBase64 := base64.StdEncoding.EncodeToString(aad)

	// Log the result for debugging
	js.Global().Get("console").Call("log", "Encryption result from Go:")
	js.Global().Get("console").Call("log", "- Ciphertext:", ciphertextBase64)
	js.Global().Get("console").Call("log", "- Nonce:", nonceBase64)
	js.Global().Get("console").Call("log", "- AAD:", aadBase64)

	// Create a callback function to return the result
	callback := js.Global().Get("Function").New(`
		return function(ciphertext, nonce, aad) {
			return {
				ciphertext: ciphertext,
				nonce: nonce,
				aad: aad
			};
		};
	`).Invoke()

	// Call the callback function with the result
	return callback.Invoke(ciphertextBase64, nonceBase64, aadBase64)
}

// decryptSecret decrypts a secret using AES-256-GCM
func decryptSecret(this js.Value, args []js.Value) interface{} {
	js.Global().Get("console").Call("log", "decryptSecret called with args length:", len(args))

	if len(args) < 4 {
		return js.Error{Value: js.ValueOf("Missing arguments: key, ciphertext, nonce, aad")}
	}

	// Decode key from base64
	keyBase64 := args[0].String()
	js.Global().Get("console").Call("log", "Key base64 length:", len(keyBase64))
	js.Global().Get("console").Call("log", "Key base64 value:", keyBase64)
	key, err := safeDecodeBase64(keyBase64)
	if err != nil {
		js.Global().Get("console").Call("log", "Key decode error:", err.Error())
		return js.Error{Value: js.ValueOf("Invalid key: " + err.Error())}
	}

	// Decode ciphertext from base64
	ciphertextBase64 := args[1].String()
	js.Global().Get("console").Call("log", "Ciphertext base64 length:", len(ciphertextBase64))
	js.Global().Get("console").Call("log", "Ciphertext base64 value:", ciphertextBase64)
	ciphertext, err := safeDecodeBase64(ciphertextBase64)
	if err != nil {
		js.Global().Get("console").Call("log", "Ciphertext decode error:", err.Error())
		return js.Error{Value: js.ValueOf("Invalid ciphertext: " + err.Error())}
	}

	// Decode nonce from base64
	nonceBase64 := args[2].String()
	js.Global().Get("console").Call("log", "Nonce base64 length:", len(nonceBase64))
	js.Global().Get("console").Call("log", "Nonce base64 value:", nonceBase64)
	nonce, err := safeDecodeBase64(nonceBase64)
	if err != nil {
		js.Global().Get("console").Call("log", "Nonce decode error:", err.Error())
		return js.Error{Value: js.ValueOf("Invalid nonce: " + err.Error())}
	}

	// Decode AAD from base64
	aadBase64 := args[3].String()
	js.Global().Get("console").Call("log", "AAD base64 length:", len(aadBase64))
	js.Global().Get("console").Call("log", "AAD base64 value:", aadBase64)
	aad, err := safeDecodeBase64(aadBase64)
	if err != nil {
		js.Global().Get("console").Call("log", "AAD decode error:", err.Error())
		return js.Error{Value: js.ValueOf("Invalid AAD: " + err.Error())}
	}

	// Create AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		js.Global().Get("console").Call("log", "AES cipher error:", err.Error())
		return js.Error{Value: js.ValueOf("AES cipher creation failed: " + err.Error())}
	}

	// Create GCM mode
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		js.Global().Get("console").Call("log", "GCM mode error:", err.Error())
		return js.Error{Value: js.ValueOf("GCM mode creation failed: " + err.Error())}
	}

	// Decrypt
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		js.Global().Get("console").Call("log", "Decryption error:", err.Error())
		return js.Error{Value: js.ValueOf("Decryption failed: " + err.Error())}
	}

	// Return base64 encoded plaintext
	result := base64.StdEncoding.EncodeToString(plaintext)
	js.Global().Get("console").Call("log", "Decryption result:", result)
	return js.ValueOf(result)
}
