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

	"go.ptx.dk/ssh-jwt"
)

// Version information
const Version = "0.1.0"

func main() {
	sshjwt.RegisterSigner()

	if err := root(); err != nil {
		log.Fatalf("%+v\n", err)
	}
}

var getDefaultAgent = sshjwt.DefaultAgent

var (
	flagKey  string
	flagPass string
	jwkKeyID string
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
	
	var key interface{}
	if pass != "" {
		// Try with password first if provided
		key, err = ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(pass))
	} else {
		// Try without password first
		key, err = ssh.ParseRawPrivateKey(data)
		if err != nil {
			// If it fails and we don't have a password, try with empty password
			// This handles some edge cases where the key might expect empty passphrase
			key, err = ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(""))
		}
	}
	
	if err != nil {
		return nil, err
	}
	err = ring.AddKey(agent.AddedKey{PrivateKey: key})
	return ring, err
}

func root() error {
	cmd := &cobra.Command{
		Use: "ssh-jwt",
		Version: Version,
	}
	
	// Create JWK command with its own flags
	jwkCommand := &cobra.Command{
		Use:   "jwk",
		Short: "Generate JSON Web Key (JWK) from SSH agent key",
		RunE:  jwkCmd,
	}
	jwkCommand.Flags().StringVar(&jwkKeyID, "kid", "", "Override the key ID (defaults to SSH key comment)")
	
	cmd.AddCommand(
		&cobra.Command{
			Use:  "sign",
			RunE: signCmd,
		},
		&cobra.Command{
			Use:  "signjson [input] [output]",
			RunE: signJsonCmd,
		},
		jwkCommand,
		&cobra.Command{
			Use:  "verify",
			RunE: verifyCmd,
			Args: cobra.MinimumNArgs(1),
		},
		&cobra.Command{
			Use:   "version",
			Short: "Print version information",
			Run: func(cmd *cobra.Command, args []string) {
				fmt.Printf("ssh-jwt version %s\n", Version)
			},
		},
	)
	cmd.PersistentFlags().StringVar(&flagKey, "key", "", "")
	cmd.PersistentFlags().StringVar(&flagPass, "pass", "", "")
	return cmd.Execute()
}
