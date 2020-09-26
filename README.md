# ssh-jwt

A library and command to generate jwt tokens using ssh key or ssh-agent

## Usage

### Library Usage

import as `sshjwt "go.ptx.dk/sh-jwt"`

#### Sign token

The following example connects to the ssh-agent and signs a token with the first available key.

```go
	agent, err := sshjwt.DefaultAgent()
	if err != nil {
		return err
	}
	key, err := agent.FirstKey()
	if err != nil {
		return err
	}
	claims := jwt.MapClaims{
		"email": "peter@ptx.dk",
	}
	token := jwt.NewWithClaims(sshjwt.SSHSigningMethod, claims)
	str, err := token.SignedString(key)
	if err != nil {
		return err
	}
```

#### Verify

The following example verifies a token using any of the keys loaded in the ssh agent

```go
	sshjwt.RegisterSigner() // Registers the SSHSigningMethod as the default for RS256 tokens 

	agent, err := sshjwt.DefaultAgent()
	if err != nil {
		return err
	}
	tok, err := jwt.Parse(token, func(token *jwt.Token) (interface{}, error) {
		return agent.AllKeys()
	})
```

### Cli command

#### Sign claims

`ssh-jwt sign key=value`

#### Verify

`ssh-jwt verify <token>`

## TODO

- Create upstream patch to fix type of `agent.NewKeyring` (it should be `ExtendedAgent` instead of `Agent`)
