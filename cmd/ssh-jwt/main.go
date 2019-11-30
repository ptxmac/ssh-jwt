package main

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	sshjwt "github.com/ptxmac/ssh-jwt"
)

func main() {
	if err := root(); err != nil {
		log.Fatalf("%+v\n", err)
	}
}

var getDefaultAgent = sshjwt.DefaultAgent

var (
	flagKey  string
	flagPass string
)

func isFile(p string) (bool, error) {
	_, err := os.Stat(p)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, err
}

func getAgent() (sshjwt.Agent, error) {
	if flagKey != "" {
		// if it's a file that exists
		b, err := isFile(flagKey)
		if err != nil {
			return nil, err
		}
		if b {
			return keyringWithKey(flagKey, flagPass)
		} else {
			return nil, fmt.Errorf("file not found: %w", err)
		}
		// TODO use as default key name
	}

	return getDefaultAgent()
}

func keyringWithKey(keyFile, pass string) (sshjwt.Agent, error) {
	ring := sshjwt.NewKeyring()
	data, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(pass))
	if err != nil {
		return nil, err
	}
	err = ring.AddKey(agent.AddedKey{PrivateKey: key})
	return ring, err
}

func root() error {
	cmd := &cobra.Command{
		Use: "ssh-jwt",
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:  "sign",
			RunE: signCmd,
		},
		&cobra.Command{
			Use:  "verify",
			RunE: verifyCmd,
			Args: cobra.MinimumNArgs(1),
		},
	)
	cmd.PersistentFlags().StringVar(&flagKey, "key", "", "")
	cmd.PersistentFlags().StringVar(&flagPass, "pass", "", "")
	return cmd.Execute()
}
