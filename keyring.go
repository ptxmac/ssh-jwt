package sshjwt

import (
	"net"

	sshagent "golang.org/x/crypto/ssh/agent"
)

type Keyring interface {
	Agent
	AddKey(key sshagent.AddedKey) error
}

type keyring struct {
	agent
}

func (k *keyring) AddKey(key sshagent.AddedKey) error {
	return k.agent.client.Add(key)
}

func NewKeyring() Keyring {
	c1, c2 := net.Pipe()

	backend := sshagent.NewKeyring()
	go sshagent.ServeAgent(backend, c2)

	return &keyring{
		agent: agent{client: sshagent.NewClient(c1)},
	}
}
