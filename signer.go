package sshjwt

import (
	"fmt"

	"github.com/dgrijalva/jwt-go"
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

func (s *sshSigner) Verify(signingString, signature string, key interface{}) error {
	switch key := key.(type) {
	case *keyWrapper:
		return verifyKey(signingString, signature, key)
	case []*keyWrapper:
		return verifyAnyKey(signingString, signature, key)
	}
	return fmt.Errorf("unexpected key type: %T", key)

}

func verifyAnyKey(signingString string, signature string, keys []*keyWrapper) error {
	for _, key := range keys {
		if err := verifyKey(signingString, signature, key); err == nil {
			return nil
		}
	}
	return fmt.Errorf("found no valid key")
}

func verifyKey(signingString string, signature string, key *keyWrapper) error {
	sigBlob, err := jwt.DecodeSegment(signature)
	if err != nil {
		return err
	}
	sig := &ssh.Signature{
		Format: "rsa-sha2-256",
		Blob:   sigBlob,
	}
	return key.pubKey.Verify([]byte(signingString), sig)
}

func (s *sshSigner) Sign(signingString string, key interface{}) (string, error) {
	w, ok := key.(*keyWrapper)
	if !ok {
		return "", fmt.Errorf("unexpected key type: %t", key)
	}
	sig, err := w.getClient().SignWithFlags(
		w.pubKey,
		[]byte(signingString),
		sshagent.SignatureFlagRsaSha256,
	)
	if err != nil {
		return "", err
	}
	return jwt.EncodeSegment(sig.Blob), nil
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
