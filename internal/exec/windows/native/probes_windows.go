//go:build windows

package native

import (
	"context"
	"unsafe"

	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"golang.org/x/sys/windows"
)

var (
	modwtsapi32             = windows.NewLazySystemDLL("wtsapi32.dll")
	procWTSOpenServerW      = modwtsapi32.NewProc("WTSOpenServerW")
	procWTSCloseServer      = modwtsapi32.NewProc("WTSCloseServer")
	procWTSEnumSessionsW    = modwtsapi32.NewProc("WTSEnumerateSessionsW")
	procWTSFreeMemory       = modwtsapi32.NewProc("WTSFreeMemory")
	modkernel32native       = windows.NewLazySystemDLL("kernel32.dll")
	procGetDiskFreeSpaceExW = modkernel32native.NewProc("GetDiskFreeSpaceExW")
)

type wtsSessionInfo struct {
	sessionID uint32
	name      uintptr
	state     uint32
}

// Probes performs the direct preflight checks from the Windows host
// remoteexec runs on.
type Probes struct{}

func (Probes) Close() {}

func (Probes) Authenticate(ctx context.Context, target string, creds credentials.Credentials) error {
	if creds.Password == "" {
		if creds.Username == "" {
			return nil
		}
		return errs.New(errs.Authentication, "credential auth requires a password")
	}
	ident, err := logon(creds)
	if err != nil {
		return err
	}
	ident.close()
	return nil
}

func (Probes) LocalAdmin(ctx context.Context, target string, creds credentials.Credentials) (bool, error) {
	ident, err := logonIfNeeded(creds)
	if err != nil {
		return false, err
	}
	defer ident.close()
	var admin bool
	ident.run(func() error {
		// The ADMIN$ administrative share is only accessible to local
		// administrators, so a successful open proves the privilege.
		handle, err := windows.CreateFile(windows.StringToUTF16Ptr(`\\`+target+`\ADMIN$`), windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			return nil
		}
		windows.CloseHandle(handle)
		admin = true
		return nil
	})
	return admin, nil
}

func (Probes) ServiceState(ctx context.Context, target, name string, creds credentials.Credentials) (string, bool, error) {
	ident, err := logonIfNeeded(creds)
	if err != nil {
		return "", false, err
	}
	defer ident.close()
	var (
		state string
		found bool
		err2  error
	)
	ident.run(func() error {
		scm, err := openSCManager(target)
		if err != nil {
			err2 = err
			return nil
		}
		defer closeService(scm)
		config, err := scmQueryConfig(scm, name)
		if err != nil {
			// A missing service is a valid answer, not a probe failure.
			return nil
		}
		found = true
		state = config.State
		return nil
	})
	return state, found, err2
}

func (Probes) ServiceImagePath(ctx context.Context, target, name string, creds credentials.Credentials) (string, bool, error) {
	ident, err := logonIfNeeded(creds)
	if err != nil {
		return "", false, err
	}
	defer ident.close()
	var (
		path  string
		found bool
		err2  error
	)
	ident.run(func() error {
		scm, err := openSCManager(target)
		if err != nil {
			err2 = err
			return nil
		}
		defer closeService(scm)
		config, err := scmQueryConfig(scm, name)
		if err != nil {
			return nil
		}
		found = true
		path = config.PathName
		return nil
	})
	return path, found, err2
}

func (Probes) ActiveSession(ctx context.Context, target string, creds credentials.Credentials) (bool, error) {
	server, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return false, errs.New(errs.Reachability, "invalid target: %v", err)
	}
	ident, err := logonIfNeeded(creds)
	if err != nil {
		return false, err
	}
	defer ident.close()
	var active bool
	var probeErr error
	if err := ident.run(func() error {
		handle, _, _ := procWTSOpenServerW.Call(uintptr(unsafe.Pointer(server)))
		if handle == 0 {
			probeErr = errs.New(errs.Reachability, "WTSOpenServerW failed for %s", target)
			return nil
		}
		defer procWTSCloseServer.Call(handle)
		var (
			count    uint32
			sessions unsafe.Pointer
		)
		r, _, callErr := procWTSEnumSessionsW.Call(handle, 0, 1, uintptr(unsafe.Pointer(&sessions)), uintptr(unsafe.Pointer(&count)))
		if r == 0 {
			probeErr = errs.Wrap(errs.Reachability, callErr)
			return nil
		}
		defer procWTSFreeMemory.Call(uintptr(sessions))
		for i := uint32(0); i < count; i++ {
			session := (*wtsSessionInfo)(unsafe.Add(sessions, uintptr(i)*unsafe.Sizeof(wtsSessionInfo{})))
			if session.state == 0 { // WTSActive
				active = true
				break
			}
		}
		return nil
	}); err != nil {
		return false, err
	}
	return active, probeErr
}

func (Probes) DiskFree(ctx context.Context, target, remotePath string, creds credentials.Credentials) (uint64, error) {
	ident, err := logonIfNeeded(creds)
	if err != nil {
		return 0, err
	}
	defer ident.close()
	var free uint64
	var diskErr error
	if err := ident.run(func() error {
		path, err := windows.UTF16PtrFromString(uncPath(target, remotePath))
		if err != nil {
			diskErr = errs.New(errs.Validation, "invalid remote staging path: %v", err)
			return nil
		}
		var freeBytes, totalBytes, available uint64
		r, _, callErr := procGetDiskFreeSpaceExW.Call(
			uintptr(unsafe.Pointer(path)),
			uintptr(unsafe.Pointer(&freeBytes)),
			uintptr(unsafe.Pointer(&totalBytes)),
			uintptr(unsafe.Pointer(&available)),
		)
		if r == 0 {
			diskErr = errs.Wrap(errs.Reachability, callErr)
			return nil
		}
		free = freeBytes
		return nil
	}); err != nil {
		return 0, err
	}
	return free, diskErr
}

func (Probes) FileExists(ctx context.Context, target, path string, creds credentials.Credentials) (bool, error) {
	ident, err := logonIfNeeded(creds)
	if err != nil {
		return false, err
	}
	defer ident.close()
	return fileExists(ctx, target, path, ident)
}

func (Probes) Glob(ctx context.Context, target, pattern string, creds credentials.Credentials) ([]string, error) {
	ident, err := logonIfNeeded(creds)
	if err != nil {
		return nil, err
	}
	defer ident.close()
	return globFiles(ctx, target, pattern, ident)
}

// logonIfNeeded logs on only when a password is supplied; otherwise the
// caller identity is used. It never fails on token-mode probes.
func logonIfNeeded(creds credentials.Credentials) (identity, error) {
	if creds.Password == "" {
		return identity{}, nil
	}
	return logon(creds)
}
