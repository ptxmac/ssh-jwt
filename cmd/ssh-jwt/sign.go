package main

import (
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/spf13/cobra"

	"go.ptx.dk/ssh-jwt"
)

func split(arg string) (string, string, error) {
	parts := strings.Split(arg, "=")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("argument must be key=value")
	}
	return parts[0], parts[1], nil
}

func signCmd(cmd *cobra.Command, args []string) error {
	claims := jwt.MapClaims{}
	for _, arg := range args {
		k, v, err := split(arg)
		if err != nil {
			return err
		}
		claims[k] = v
	}
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

	fmt.Println(str)
	return nil
}
