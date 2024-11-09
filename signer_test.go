package sshjwt

import (
	"crypto/rand"
	"crypto/rsa"
	"net"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sshagent "golang.org/x/crypto/ssh/agent"
)

var _ jwt.SigningMethod = &sshSigner{} // type check

func startTestAgent(t *testing.T) (sshagent.ExtendedAgent, func()) {
	c1, c2 := net.Pipe() // Use real socket?
	backend := sshagent.NewKeyring()
	go sshagent.ServeAgent(backend, c2)
	return sshagent.NewClient(c1), func() {
		c1.Close()
		c2.Close()
	}
}

func TestSSHSigner(t *testing.T) {
	// test agent
	client, cleanup := startTestAgent(t)
	defer cleanup()
	a := agent{
		client: client,
	}

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NoError(t, client.Add(sshagent.AddedKey{
		PrivateKey: priv,
	}))

	k, err := a.FirstKey()
	require.NoError(t, err)
	s := &sshSigner{}
	signature, err := s.Sign("test", k)
	assert.NoError(t, err)

	// verify the signature
	all, err := a.AllKeys()
	require.NoError(t, err)
	assert.NoError(t, s.Verify("test", signature, all))
}
