package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"go.ptx.dk/ssh-jwt"
)

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`           // Key Type
	Use string `json:"use,omitempty"` // Public Key Use
	Alg string `json:"alg,omitempty"` // Algorithm
	Kid string `json:"kid,omitempty"` // Key ID
	N   string `json:"n"`             // RSA modulus
	E   string `json:"e"`             // RSA exponent
}

// JWKSet represents a JSON Web Key Set
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

func jwkCmd(cmd *cobra.Command, args []string) error {
	// Get the SSH agent connection 
	agent, err := getAgent()
	if err != nil {
		return err
	}

	// Get the first key with comment information
	keyWrapper, err := agent.FirstKey()
	if err != nil {
		return err
	}

	// Use the comment from the SSH agent key for a more descriptive key ID
	// But allow override with the --kid flag
	var keyComment string
	if jwkKeyID != "" {
		keyComment = jwkKeyID
	} else {
		keyComment = keyWrapper.Comment()
	}

	// Convert SSH public key to JWK format
	jwk, err := sshPublicKeyToJWK(keyWrapper.PublicKey(), keyComment)
	if err != nil {
		return err
	}

	output, err := json.MarshalIndent(jwk, "", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(output))
	return nil
}

func sshPublicKeyToJWK(pubKey ssh.PublicKey, keyComment string) (*JWK, error) {
	// Try to get the crypto public key
	cryptoPublicKey, ok := pubKey.(ssh.CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("key does not implement CryptoPublicKey interface")
	}
	
	// Parse the SSH public key to get the underlying crypto key
	cryptoKey := cryptoPublicKey.CryptoPublicKey()
	
	rsaKey, ok := cryptoKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("only RSA keys are supported, got %T", cryptoKey)
	}

	// Generate key ID from SSH key comment if available, otherwise use hash
	keyID := generateKeyIDFromComment(keyComment, pubKey)

	// Convert RSA key to JWK format
	jwk := &JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: sshjwt.SSHSigningMethod.Alg(), // Use the same algorithm as the signer
		Kid: keyID,
		N:   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	}

	return jwk, nil
}

func generateKeyIDFromComment(keyComment string, pubKey ssh.PublicKey) string {
	if keyComment != "" {
		// Use the comment directly as key ID if provided (via --key-id flag or SSH comment)
		return keyComment
	}
	
	// Fallback to hash-based ID if no comment
	return generateKeyID(pubKey)
}

func generateKeyID(pubKey ssh.PublicKey) string {
	// Generate SHA256 fingerprint similar to SSH fingerprint
	hash := sha256.Sum256(pubKey.Marshal())
	return base64.RawURLEncoding.EncodeToString(hash[:])[:8]
}
