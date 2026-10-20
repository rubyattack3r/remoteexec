package credentials

import (
	"errors"
	"fmt"
	"strings"
)

// Credentials are deliberately excluded from all output and error strings.
type Credentials struct {
	Domain         string
	Username       string
	Password       string
	NTHash         string
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
	if c.Password == "" && c.NTHash == "" {
		return errors.New("credential validation: provide exactly one of --password or --nt-hash")
	}
	if c.Password != "" && c.NTHash != "" {
		return errors.New("credential validation: --password and --nt-hash are mutually exclusive")
	}
	if c.NTHash != "" && len(c.NTHash) != 32 {
		return fmt.Errorf("credential validation: --nt-hash must contain 32 hexadecimal characters")
	}
	for _, r := range c.NTHash {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return errors.New("credential validation: --nt-hash must contain only hexadecimal characters")
		}
	}
	return nil
}

// ValidateSSH accepts one explicit SSH authentication method. Agent and
// implicit home-directory key discovery are intentionally not used.
func (c Credentials) ValidateSSH() error {
	if strings.TrimSpace(c.Username) == "" {
		return errors.New("credential validation: --username is required")
	}
	if c.Domain != "" || c.NTHash != "" {
		return errors.New("credential validation: --domain and --nt-hash are not valid for SSH")
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
	for _, secret := range []string{c.Password, c.NTHash} {
		if secret != "" {
			message = strings.ReplaceAll(message, secret, "[REDACTED]")
		}
	}
	return message
}
