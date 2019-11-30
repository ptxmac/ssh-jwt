# ssh-jwt

A library and command to generate jwt tokens using ssh key or ssh-agent

## Usage

### Cli command

#### Sign claims

`ssh-jwt sign key=value`

#### Verify

`ssh-jwt verify <token>`

## TODO

- Create upstream patch to fix type of `agent.NewKeyring` (it should be `ExtendedAgent` instead of `Agent`)
