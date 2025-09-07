package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"

	"go.ptx.dk/ssh-jwt"
)

func TestSignJsonCmd(t *testing.T) {
	// Set up test key ring like other tests
	ring := sshjwt.NewKeyring()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NoError(t, ring.AddKey(agent.AddedKey{PrivateKey: priv}))

	getDefaultAgent = func() (agent sshjwt.Agent, err error) {
		return ring, nil
	}

	// Test simple JSON payload
	tempDir := t.TempDir()
	inputFile := filepath.Join(tempDir, "input.json")
	outputFile := filepath.Join(tempDir, "output.jwt")

	claims := `{
		"aud": "https://auth.example.com/oauth2/token",
		"email": "test@example.com",
		"sub": "test@example.com",
		"iss": "test@example.com",
		"exp": 1757263188,
		"iat": 1757259588
	}`

	// Write test JSON to file
	err = os.WriteFile(inputFile, []byte(claims), 0644)
	require.NoError(t, err)

	// Test with input file and output file
	err = signJsonCmd(nil, []string{inputFile, outputFile})
	assert.NoError(t, err)

	// Verify output file exists and contains JWT-like data
	output, err := os.ReadFile(outputFile)
	require.NoError(t, err)
	assert.True(t, len(output) > 0)
	assert.True(t, bytes.Contains(output, []byte(".")), "Output should contain JWT separators")
	assert.True(t, strings.HasPrefix(string(output), "eyJ"), "JWT should start with base64 header")
}

func TestSignJsonStdio(t *testing.T) {
	// Set up test key ring
	ring := sshjwt.NewKeyring()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NoError(t, ring.AddKey(agent.AddedKey{PrivateKey: priv}))

	getDefaultAgent = func() (agent sshjwt.Agent, err error) {
		return ring, nil
	}

	// Test with stdin/stdout by redirecting
	claims := `{"sub": "user", "exp": 1757263188}`

	// Redirect stdin
	oldStdin := os.Stdin
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdin = r

	// Write claims to stdin
	go func() {
		defer w.Close()
		w.Write([]byte(claims))
	}()

	// Redirect stdout
	oldStdout := os.Stdout
	r2, w2, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w2

	// Run command
	err = signJsonCmd(nil, []string{})

	// Restore original stdin/stdout
	os.Stdin = oldStdin
	os.Stdout = oldStdout
	w2.Close()

	// Read output
	output, err := io.ReadAll(r2)
	require.NoError(t, err)

	assert.True(t, len(output) > 0)
	assert.True(t, bytes.Contains(output, []byte(".")), "Output should contain JWT separators")
}
