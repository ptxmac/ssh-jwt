package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"

	"go.ptx.dk/ssh-jwt"
)

func TestJwkCmd(t *testing.T) {
	// Set up test key ring like other tests
	ring := sshjwt.NewKeyring()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NoError(t, ring.AddKey(agent.AddedKey{PrivateKey: priv}))

	getDefaultAgent = func() (agent sshjwt.Agent, err error) {
		return ring, nil
	}

	// Capture output by temporarily redirecting stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	// Run the JWK command
	err = jwkCmd(nil, []string{})
	
	// Restore stdout
	os.Stdout = oldStdout
	w.Close()

	// Read the output
	output, err := io.ReadAll(r)
	require.NoError(t, err)

	// Parse the JSON output
	var jwk JWK
	err = json.Unmarshal(output, &jwk)
	require.NoError(t, err)

	// Verify the JWK structure
	assert.Equal(t, "RSA", jwk.Kty)
	assert.Equal(t, "sig", jwk.Use)
	assert.Equal(t, "RS256", jwk.Alg)
	assert.NotEmpty(t, jwk.Kid)
	assert.NotEmpty(t, jwk.N)
	assert.Equal(t, "AQAB", jwk.E) // Standard RSA exponent 65537 in base64url

	// Verify the output is valid JSON
	assert.True(t, json.Valid(output))
	assert.True(t, strings.Contains(string(output), "\"kty\": \"RSA\""))
}

func TestJwkCmdWithCustomKid(t *testing.T) {
	// Set up test key ring like other tests
	ring := sshjwt.NewKeyring()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NoError(t, ring.AddKey(agent.AddedKey{PrivateKey: priv}))

	getDefaultAgent = func() (agent sshjwt.Agent, err error) {
		return ring, nil
	}

	// Set custom kid
	jwkKeyID = "test-custom-kid"
	defer func() { jwkKeyID = "" }() // Reset after test

	// Capture output by temporarily redirecting stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	// Run the JWK command
	err = jwkCmd(nil, []string{})
	
	// Restore stdout
	os.Stdout = oldStdout
	w.Close()

	// Read the output
	output, err := io.ReadAll(r)
	require.NoError(t, err)

	// Parse the JSON output
	var jwk JWK
	err = json.Unmarshal(output, &jwk)
	require.NoError(t, err)

	// Verify the custom kid is used
	assert.Equal(t, "test-custom-kid", jwk.Kid)
	assert.Equal(t, "RSA", jwk.Kty)
	assert.Equal(t, "sig", jwk.Use)
	assert.Equal(t, "RS256", jwk.Alg)
}
