package sshjwt

import (
	"fmt"
	"net"
	"os"

	sshagent "golang.org/x/crypto/ssh/agent"
)

type Agent interface {
	FirstKey() (*keyWrapper, error)
	AllKeys() ([]*keyWrapper, error)
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

func (a *agent) wrapKey(key *sshagent.Key) *keyWrapper {
	return &keyWrapper{
		agent:  a,
		pubKey: key,
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
