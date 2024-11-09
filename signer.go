package sshjwt

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type keyWrapper struct {
	pubKey ssh.PublicKey
	agent  *agent
}

func (w *keyWrapper) getClient() sshagent.ExtendedAgent {
	return w.agent.client
}

type sshSigner struct{}

func (s *sshSigner) Verify(signingString string, signature []byte, key interface{}) error {
	switch key := key.(type) {
	case ssh.PublicKey:
		return verifyKey(signingString, signature, key)
	case []ssh.PublicKey:
		var keys []ssh.PublicKey
		for _, k := range key {
			keys = append(keys, k)
		}
		return verifyAnyKey(signingString, signature, keys)
	case *keyWrapper:
		return verifyKey(signingString, signature, key.pubKey)
	case []*keyWrapper:
		var keys []ssh.PublicKey
		for _, k := range key {
			keys = append(keys, k.pubKey)
		}
		return verifyAnyKey(signingString, signature, keys)
	}
	return fmt.Errorf("unexpected key type: %T", key)
}

func verifyAnyKey(signingString string, signature []byte, keys []ssh.PublicKey) error {
	for _, key := range keys {
		if err := verifyKey(signingString, signature, key); err == nil {
			return nil
		}
	}
	return fmt.Errorf("found no valid key")
}

func verifyKey(signingString string, signature []byte, key ssh.PublicKey) error {
	sig := &ssh.Signature{
		Format: "rsa-sha2-256",
		Blob:   signature,
	}
	return key.Verify([]byte(signingString), sig)
}

func (s *sshSigner) Sign(signingString string, key interface{}) ([]byte, error) {
	w, ok := key.(*keyWrapper)
	if !ok {
		return nil, fmt.Errorf("unexpected key type: %t", key)
	}
	sig, err := w.getClient().SignWithFlags(
		w.pubKey,
		[]byte(signingString),
		sshagent.SignatureFlagRsaSha256,
	)
	if err != nil {
		return nil, err
	}
	return sig.Blob, nil
}

func (s *sshSigner) Alg() string {
	return "RS256"
}

var SSHSigningMethod *sshSigner

func RegisterSigner() {
	SSHSigningMethod = &sshSigner{}
	jwt.RegisterSigningMethod(SSHSigningMethod.Alg(), func() jwt.SigningMethod {
		return SSHSigningMethod
	})
}
