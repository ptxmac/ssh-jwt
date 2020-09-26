package main

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh/agent"

	"go.ptx.dk/ssh-jwt"
)

func TestVerify(t *testing.T) {
	ring := sshjwt.NewKeyring()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NoError(t, ring.AddKey(agent.AddedKey{PrivateKey: priv}))

	getDefaultAgent = func() (agent sshjwt.Agent, err error) {
		return ring, nil
	}

	token := jwt.NewWithClaims(sshjwt.SSHSigningMethod, nil)
	key, err := ring.FirstKey()
	require.NoError(t, err)
	str, err := token.SignedString(key)
	require.NoError(t, err)

	err = verifyCmd(nil, []string{str})
	assert.NoError(t, err)
}
