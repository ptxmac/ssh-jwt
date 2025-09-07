package sshjwt

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	sshagent "golang.org/x/crypto/ssh/agent"
)

type Agent interface {
	FirstKey() (*keyWrapper, error)
	AllKeys() ([]*keyWrapper, error)
	WrapPubKey(pub ssh.PublicKey) *keyWrapper
}

type agent struct {
	client sshagent.ExtendedAgent
}

func (a *agent) AllKeys() ([]*keyWrapper, error) {
	keys, err := a.client.List()
	if err != nil {
		return nil, err
	}
	var res []*keyWrapper
	for _, key := range keys {
		res = append(res, a.wrapKey(key))
	}
	return res, nil
}

func (a *agent) FirstKey() (*keyWrapper, error) {
	keys, err := a.client.List()
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no keys found")
	}
	return a.wrapKey(keys[0]), nil
}

func (a *agent) WrapPubKey(pub ssh.PublicKey) *keyWrapper {
	return &keyWrapper{
		agent:   a,
		pubKey:  pub,
		comment: "", // No comment available when wrapping just a public key
	}
}

func (a *agent) wrapKey(key *sshagent.Key) *keyWrapper {
	// Parse the agent key to get the proper ssh.PublicKey
	pubKey, err := ssh.ParsePublicKey(key.Blob)
	if err != nil {
		// If we can't parse the key, fall back to the original behavior
		// This shouldn't happen in normal cases, but provides resilience
		pubKey = key
	}
	
	return &keyWrapper{
		agent:   a,
		pubKey:  pubKey,
		comment: key.Comment,
	}
}

func DefaultAgent() (Agent, error) {
	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, err
	}
	return NewAgent(sshagent.NewClient(conn)), nil
}

func NewAgent(client sshagent.ExtendedAgent) Agent {
	return &agent{client: client}
}
