package main

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
)

// EncryptedSecret represents an encrypted secret with its ID, salt, and encrypted data
type EncryptedSecret struct {
	ID         string // base64url (16 bytes)
	Salt       string // base64url (32 bytes)
	Ciphertext string // base64 encoded encrypted secret
	Nonce      string // base64 encoded nonce
	AAD        string // base64 encoded AAD
}

// SecretStore is an in-memory store for secrets
type SecretStore struct {
	secretsByUser map[string][]EncryptedSecret // map[username][]EncryptedSecret
	mu            sync.RWMutex
}

// NewSecretStore creates a new secret store
func NewSecretStore() *SecretStore {
	return &SecretStore{
		secretsByUser: make(map[string][]EncryptedSecret),
	}
}

// AddSecret adds a new secret for a user
func (s *SecretStore) AddSecret(username string, secret EncryptedSecret) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.secretsByUser[username]; !ok {
		s.secretsByUser[username] = []EncryptedSecret{}
	}

	s.secretsByUser[username] = append(s.secretsByUser[username], secret)
}

// GetSecretByID returns a secret by its ID for a specific user
func (s *SecretStore) GetSecretByID(username, secretID string) (*EncryptedSecret, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	secrets, ok := s.secretsByUser[username]
	if !ok {
		return nil, false
	}

	for i, secret := range secrets {
		if secret.ID == secretID {
			return &secrets[i], true
		}
	}

	return nil, false
}

// RegisterSecretHandlers registers the secret-related HTTP handlers
func RegisterSecretHandlers(secretStore *SecretStore, userStore *UserStore, sessionStore *SessionStore, logger *log.Logger) {
	// Handler for storing an encrypted secret
	http.HandleFunc("/api/secret/store", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Get username from session cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			logger.Printf("No session cookie found: %v", err)
			http.Error(w, "Not logged in", http.StatusUnauthorized)
			return
		}

		// Get session data
		sessionID := cookie.Value
		session, ok := sessionStore.GetSession(sessionID)
		if !ok {
			logger.Printf("Session not found: %s", sessionID)
			http.Error(w, "Session not found", http.StatusUnauthorized)
			return
		}

		// Get user by ID
		_, username, ok := userStore.GetUserByID(session.UserID)
		if !ok {
			logger.Printf("User not found with ID: %x", session.UserID)
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		logger.Printf("Storing encrypted secret for user: %s", username)

		// Parse request
		var request struct {
			SecretID   string `json:"secretID"`
			Salt       string `json:"salt"`
			Ciphertext string `json:"ciphertext"`
			Nonce      string `json:"nonce"`
			AAD        string `json:"aad"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			logger.Printf("Failed to parse request: %v", err)
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Validate request fields
		if request.SecretID == "" || request.Salt == "" || request.Ciphertext == "" || request.Nonce == "" || request.AAD == "" {
			logger.Printf("Missing required fields in request")
			http.Error(w, "Missing required fields", http.StatusBadRequest)
			return
		}

		// Create and store the encrypted secret
		secret := EncryptedSecret{
			ID:         request.SecretID,
			Salt:       request.Salt,
			Ciphertext: request.Ciphertext,
			Nonce:      request.Nonce,
			AAD:        request.AAD,
		}

		secretStore.AddSecret(username, secret)
		logger.Printf("Encrypted secret stored for user %s: ID=%s", username, request.SecretID)

		// Sync storage
		if err := storageSync(userStore, secretStore, logger); err != nil {
			logger.Printf("Warning: Failed to sync storage: %v", err)
		}

		// Return success
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status": "success",
		})
	})

	// Handler for retrieving an encrypted secret
	http.HandleFunc("/api/secret/retrieve", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse request
		var request struct {
			SecretID string `json:"secretID"`
		}

		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			logger.Printf("Failed to parse request: %v", err)
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}

		// Get username from session cookie
		cookie, err := r.Cookie("session_id")
		if err != nil {
			logger.Printf("No session cookie found: %v", err)
			http.Error(w, "Not logged in", http.StatusUnauthorized)
			return
		}

		// Get session data
		sessionID := cookie.Value
		session, ok := sessionStore.GetSession(sessionID)
		if !ok {
			logger.Printf("Session not found: %s", sessionID)
			http.Error(w, "Session not found", http.StatusUnauthorized)
			return
		}

		// Get user by ID
		_, username, ok := userStore.GetUserByID(session.UserID)
		if !ok {
			logger.Printf("User not found with ID: %x", session.UserID)
			http.Error(w, "User not found", http.StatusNotFound)
			return
		}
		logger.Printf("Retrieving encrypted secret for user: %s, secretID: %s", username, request.SecretID)

		// Get secret
		secret, ok := secretStore.GetSecretByID(username, request.SecretID)
		if !ok {
			logger.Printf("Secret not found: %s", request.SecretID)
			http.Error(w, "Secret not found", http.StatusNotFound)
			return
		}

		// Return the encrypted secret
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"secretID":   secret.ID,
			"salt":       secret.Salt,
			"ciphertext": secret.Ciphertext,
			"nonce":      secret.Nonce,
			"aad":        secret.AAD,
		})
	})
}
