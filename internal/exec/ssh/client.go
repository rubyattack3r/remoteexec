package ssh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	gossh "golang.org/x/crypto/ssh"
)

type NativeConnector struct{}

func (NativeConnector) Connect(ctx context.Context, hostname string, port int, creds credentials.Credentials) (Session, error) {
	if port == 0 {
		port = engine.DefaultSSHPort
	}
	auth, err := authMethod(creds)
	if err != nil {
		return nil, err
	}
	config := &gossh.ClientConfig{User: creds.Username, Auth: []gossh.AuthMethod{auth}, HostKeyCallback: gossh.InsecureIgnoreHostKey()}
	address := net.JoinHostPort(hostname, strconv.Itoa(port))
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, errs.Wrap(errs.Reachability, fmt.Errorf("ssh connect to %s: %w", address, err))
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	clientConn, channels, requests, err := gossh.NewClientConn(conn, address, config)
	if err != nil {
		conn.Close()
		return nil, errs.Wrap(errs.Authentication, errors.New(creds.Redact("ssh handshake or authentication failed: "+err.Error())))
	}
	_ = conn.SetDeadline(time.Time{})
	return nativeSession{client: gossh.NewClient(clientConn, channels, requests)}, nil
}

func authMethod(creds credentials.Credentials) (gossh.AuthMethod, error) {
	if creds.Password != "" {
		return gossh.Password(creds.Password), nil
	}
	key, err := os.ReadFile(creds.PrivateKeyPath)
	if err != nil {
		return nil, errs.Wrap(errs.Validation, fmt.Errorf("ssh private key: %w", err))
	}
	signer, err := gossh.ParsePrivateKey(key)
	if err != nil {
		return nil, errs.Wrap(errs.Validation, fmt.Errorf("ssh private key: %w", err))
	}
	return gossh.PublicKeys(signer), nil
}

type nativeSession struct{ client *gossh.Client }

func (s nativeSession) Close() error { return s.client.Close() }

func (s nativeSession) Run(ctx context.Context, command string) error {
	session, err := s.client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	session.Stdout = io.Discard
	session.Stderr = io.Discard
	return runContext(ctx, session, command)
}

type commandSession interface {
	Run(string) error
	Signal(gossh.Signal) error
}

func runContext(ctx context.Context, session commandSession, command string) error {
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
		_ = session.Signal(gossh.SIGKILL)
		return ctx.Err()
	}
}
