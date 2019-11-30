package main

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"

	sshjwt "github.com/ptxmac/ssh-jwt"
)

func TestSign(t *testing.T) {
	ring := sshjwt.NewKeyring()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NoError(t, ring.AddKey(agent.AddedKey{PrivateKey: priv}))

	getDefaultAgent = func() (agent sshjwt.Agent, err error) {
		return ring, nil
	}

	err = signCmd(nil, []string{"key=value"})
	assert.NoError(t, err)
}
