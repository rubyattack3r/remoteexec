//go:build windows

package native

import (
	"errors"
	"runtime"
	"unsafe"

	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"golang.org/x/sys/windows"
)

var (
	modadvapi32auth  = windows.NewLazySystemDLL("advapi32.dll")
	procLogonUserW   = modadvapi32auth.NewProc("LogonUserW")
	procImpersonate  = modadvapi32auth.NewProc("ImpersonateLoggedOnUser")
	procRevertToSelf = modadvapi32auth.NewProc("RevertToSelf")
)

const (
	logon32LogonNewCredentials = 9
	logon32ProviderWinNT50     = 3
)

// identity carries an interactive logon token used for impersonation. The
// zero value means "use the token remoteexec already runs as".
type identity struct {
	token windows.Token
}

func (i identity) live() bool { return i.token != 0 }

func (i identity) close() {
	if i.live() {
		i.token.Close()
	}
}

// logon turns the supplied credentials into an impersonation token. With
// LOGON32_LOGON_NEW_CREDENTIALS the token authenticates outbound network
// accesses (SMB, SCM, RPC) while local execution keeps the caller identity.
func logon(creds credentials.Credentials) (identity, error) {
	if creds.Password == "" {
		return identity{}, errs.New(errs.Authentication, "credential auth requires a password; NT-hash-only identities are not supported by the native backend")
	}
	user, err := windows.UTF16PtrFromString(creds.Username)
	if err != nil {
		return identity{}, errs.New(errs.Authentication, "invalid username: %v", err)
	}
	var domain *uint16
	if creds.Domain != "" {
		if domain, err = windows.UTF16PtrFromString(creds.Domain); err != nil {
			return identity{}, errs.New(errs.Authentication, "invalid domain: %v", err)
		}
	}
	password, err := windows.UTF16PtrFromString(creds.Password)
	if err != nil {
		return identity{}, errs.New(errs.Authentication, "invalid password: %v", err)
	}
	var token windows.Token
	ok, _, callErr := procLogonUserW.Call(
		uintptr(unsafe.Pointer(user)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		logon32LogonNewCredentials,
		logon32ProviderWinNT50,
		uintptr(unsafe.Pointer(&token)),
	)
	// LazyProc.Call receives uintptr values, which are not GC roots. Keep the
	// UTF-16 buffers alive until LogonUserW has returned; otherwise the domain
	// buffer in particular can be reclaimed between conversion and the call.
	runtime.KeepAlive(user)
	runtime.KeepAlive(domain)
	runtime.KeepAlive(password)
	if ok == 0 {
		return identity{}, errs.Wrap(errs.Authentication, callErr)
	}
	return identity{token: token}, nil
}

// run impersonates the identity for the duration of fn so kernel32 and
// advapi32 calls authenticate against remote targets with it.
func (i identity) run(fn func() error) error {
	if !i.live() {
		return fn()
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if r, _, _ := procImpersonate.Call(uintptr(i.token)); r == 0 {
		return errs.Wrap(errs.Authentication, errors.New("ImpersonateLoggedOnUser failed"))
	}
	defer procRevertToSelf.Call()
	return fn()
}

// comIdentity renders the explicit credential pair handed to COM
// connections (SWbemLocator, ITaskService, WSMan ConnectionOptions).
func comIdentity(creds credentials.Credentials, auth engine.Auth) (user, domain, password string) {
	if auth != engine.AuthCredential || creds.Password == "" {
		return "", "", ""
	}
	if creds.Domain != "" {
		return creds.Username, creds.Domain, creds.Password
	}
	return creds.Username, "", creds.Password
}
