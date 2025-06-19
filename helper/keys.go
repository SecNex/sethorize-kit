package helper

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"path/filepath"
)

const (
	KeySize = 2048
	KeyFile = "private.key"
)

type KeyManager struct {
	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey
}

func NewKeyManager() *KeyManager {
	return &KeyManager{}
}

// LoadOrGenerateKey loads an existing Private Key or generates a new one
func (km *KeyManager) LoadOrGenerateKey() error {
	keyPath := filepath.Join(".", KeyFile)

	// Check if key file exists
	if _, err := os.Stat(keyPath); os.IsNotExist(err) {
		log.Println("Private Key not found. Generating new Private Key...")
		return km.generateAndSaveKey(keyPath)
	}

	// Load existing key
	log.Println("Loading existing Private Key...")
	return km.loadKey(keyPath)
}

// generateAndSaveKey generates a new RSA Private Key and saves it
func (km *KeyManager) generateAndSaveKey(keyPath string) error {
	// Generate RSA Private Key
	privateKey, err := rsa.GenerateKey(rand.Reader, KeySize)
	if err != nil {
		return fmt.Errorf("error generating private key: %v", err)
	}

	km.PrivateKey = privateKey
	km.PublicKey = &privateKey.PublicKey

	// Convert to PEM format
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Save Key to file
	err = os.WriteFile(keyPath, privateKeyPEM, 0600)
	if err != nil {
		return fmt.Errorf("error saving private key: %v", err)
	}

	log.Printf("Private Key successfully generated and saved to %s\n", keyPath)
	return nil
}

// loadKey loads an existing Private Key from the file
func (km *KeyManager) loadKey(keyPath string) error {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("error reading private key: %v", err)
	}

	// Decode PEM
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("invalid PEM format")
	}

	// Parse Private Key
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing private key: %v", err)
	}

	km.PrivateKey = privateKey
	km.PublicKey = &privateKey.PublicKey

	log.Printf("Private Key successfully loaded from %s\n", keyPath)
	return nil
}

// GetPrivateKey returns the Private Key
func (km *KeyManager) GetPrivateKey() *rsa.PrivateKey {
	return km.PrivateKey
}

// GetPublicKey returns the Public Key
func (km *KeyManager) GetPublicKey() *rsa.PublicKey {
	return km.PublicKey
}
