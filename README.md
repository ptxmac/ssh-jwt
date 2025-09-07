[![Go Reference](https://pkg.go.dev/badge/go.ptx.dk/ssh-jwt.svg)](https://pkg.go.dev/go.ptx.dk/ssh-jwt)
[![Github Workflow](https://github.com/ptxmac/ssh-jwt/actions/workflows/go.yml/badge.svg)](https://github.com/ptxmac/ssh-jwt/actions/workflows/go.yml)
[![codecov](https://codecov.io/gh/ptxmac/ssh-jwt/branch/master/graph/badge.svg)](https://codecov.io/gh/ptxmac/ssh-jwt)

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

#### Sign claims from command line arguments

`ssh-jwt sign key=value`
`ssh-jwt --key /path/to/private/key sign key=value`
`ssh-jwt --key /path/to/encrypted/key --pass password sign key=value`

Examples:
- `ssh-jwt sign sub=user123 aud=api`  # Using SSH agent
- `ssh-jwt --key ~/.ssh/id_rsa sign sub=user123 aud=api`  # Using local key file
- `ssh-jwt --key ~/.ssh/encrypted_key --pass mypass sign sub=user123`  # Using encrypted key

#### Sign JSON payload

`ssh-jwt signjson [input.json] [output.jwt]`
`ssh-jwt --key /path/to/private/key signjson [input.json] [output.jwt]`
`ssh-jwt --key /path/to/encrypted/key --pass password signjson [input.json] [output.jwt]`

Signs a JSON file containing JWT claims. If no files are specified, reads from stdin and writes to stdout.

Examples:
- `echo '{"sub":"user123","aud":"api"}' | ssh-jwt signjson`  # Using SSH agent
- `ssh-jwt signjson claims.json token.jwt`  # Using SSH agent
- `ssh-jwt signjson claims.json -`  # Write to stdout
- `ssh-jwt --key ~/.ssh/id_rsa signjson claims.json token.jwt`  # Using local key file
- `ssh-jwt --key ~/.ssh/encrypted_key --pass mypass signjson claims.json`  # Using encrypted key

#### Generate JSON Web Key (JWK)

`ssh-jwt jwk [--kid custom-key-id]`

Generates a JWK (JSON Web Key) from the SSH agent key for use with OAuth2/OIDC servers like Ory Hydra.

Examples:
- `ssh-jwt jwk`  # Uses SSH key comment as key ID
- `ssh-jwt jwk --kid "my-service-key"`  # Custom key ID

#### Verify tokens

`ssh-jwt verify <token>`

#### Version information

- `ssh-jwt --version` or `ssh-jwt -v`
- `ssh-jwt version`

## Recent Changes (v0.1.0)

### New Features
- **Local Key File Support**: Added support for signing with local SSH private key files using `--key` and `--pass` flags
- **Improved Key Parsing**: Enhanced key parsing to handle both encrypted and unencrypted SSH private keys
- **JWK Generation**: Added `jwk` command to generate JSON Web Keys from SSH agent keys
- **JSON Signing**: Added `signjson` command for signing JSON payloads (alternative to key=value pairs)
- **Version Support**: Added version information accessible via `--version` flag and `version` command
- **SSH Key Comments**: JWK generation uses SSH key comments as default key IDs, with `--kid` override option

### Architecture Improvements  
- **Enhanced Agent Interface**: Extended `keyWrapper` to expose SSH key comments
- **Unified Connection Handling**: Eliminated duplicate SSH agent connections
- **Better Error Handling**: Improved error messages and graceful fallbacks
- **Flexible Key Loading**: Support for both SSH agent and local key files through unified interface

### Integration
- **jwt-assertion.py Integration**: The Python JWT generator script now uses `ssh-jwt` for ALL signing operations:
  - SSH agent signing via `--key-from-agent` flag
  - Local key file signing via `--key` flag (supports SSH key formats)
  - Eliminated complex custom SSH signature parsing (200+ lines reduced to simple subprocess calls)
  - Full support for encrypted/unencrypted SSH private keys
- **Simplified Deployment**: Single binary provides complete SSH-JWT functionality for multiple use cases

## TODO

- Create upstream patch to fix type of `agent.NewKeyring` (it should be `ExtendedAgent` instead of `Agent`)
