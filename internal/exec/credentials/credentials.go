package credentials

import (
	"errors"
	"strings"
)

// Credentials are deliberately excluded from all output and error strings.
type Credentials struct {
	Domain         string
	Username       string
	Password       string
	PrivateKeyPath string
}

func (c Credentials) Validate() error {
	return c.ValidateWindows()
}

func (c Credentials) ValidateWindows() error {
	if c.PrivateKeyPath != "" {
		return errors.New("credential validation: --private-key is only valid for SSH")
	}
	if c.Username == "" {
		return errors.New("credential validation: --username is required")
	}
	if c.Password == "" {
		return errors.New("credential validation: --password is required")
	}
	return nil
}

// ValidateSSH accepts one explicit SSH authentication method. Agent and
// implicit home-directory key discovery are intentionally not used.
func (c Credentials) ValidateSSH() error {
	if strings.TrimSpace(c.Username) == "" {
		return errors.New("credential validation: --username is required")
	}
	if c.Domain != "" {
		return errors.New("credential validation: --domain is not valid for SSH")
	}
	if (c.Password == "") == (c.PrivateKeyPath == "") {
		return errors.New("credential validation: provide exactly one of --password or --private-key for SSH")
	}
	return nil
}

// Redact removes secret material from a message before it is logged, wrapped
// in an error, or written to durable storage. It must be applied at the lowest
// layer, before errors reach the engine.
func (c Credentials) Redact(message string) string {
	for _, secret := range []string{c.Password} {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[REDACTED]")
		}
	}
	return message
}
