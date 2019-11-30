package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/spf13/cobra"

	"gitlab.com/ptxmac/ssh-jwt"
)

func readToken(arg string) (string, error) {
	if arg == "-" {
		data, err := ioutil.ReadAll(os.Stdin)
		str := string(data)
		str = strings.TrimSpace(str)
		return str, err
	}
	return arg, nil
}

func verifyCmd(cmd *cobra.Command, args []string) error {
	agent, err := getAgent()

	if err != nil {
		return err
	}
	for _, arg := range args {
		token, err := readToken(arg)
		if err != nil {
			return err
		}
		if err := verifyToken(agent, token); err != nil {
			return err
		}
	}
	return nil
}

func verifyToken(agent sshjwt.Agent, token string) error {
	tok, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return agent.AllKeys()
	})
	if err != nil {
		return err
	}
	s, err := pretty(struct {
		Header map[string]interface{}
		Valid  bool
		Claims jwt.Claims
	}{
		Header: tok.Header,
		Claims: tok.Claims,
		Valid:  tok.Valid,
	})
	if err != nil {
		return err
	}
	fmt.Println(s)
	return nil
}

func pretty(obj interface{}) (string, error) {
	dat, err := json.MarshalIndent(obj, "", "  ")
	return string(dat), err
}
