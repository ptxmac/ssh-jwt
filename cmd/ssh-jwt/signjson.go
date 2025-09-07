package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/spf13/cobra"

	"go.ptx.dk/ssh-jwt"
)

func signJsonCmd(cmd *cobra.Command, args []string) error {
	var input io.Reader = os.Stdin

	// Handle input file
	if len(args) > 0 && args[0] != "-" {
		file, err := os.Open(args[0])
		if err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		}
		defer file.Close()
		input = file
	}

	// Read JSON from input
	data, err := io.ReadAll(input)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	// Parse JSON into claims map
	var claims jwt.MapClaims
	if err := json.Unmarshal(data, &claims); err != nil {
		return fmt.Errorf("invalid JSON payload: %w", err)
	}

	// Create token with claims (same as sign.go)
	token := jwt.NewWithClaims(sshjwt.SSHSigningMethod, claims)

	agent, err := getAgent()
	if err != nil {
		return err
	}

	key, err := agent.FirstKey()
	if err != nil {
		return err
	}

	str, err := token.SignedString(key)
	if err != nil {
		return err
	}

	// Handle output file or stdout
	var output io.Writer = os.Stdout
	if len(args) > 1 && args[1] != "-" {
		file, err := os.Create(args[1])
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()
		output = file
	}

	_, err = fmt.Fprintln(output, str)
	return err
}
