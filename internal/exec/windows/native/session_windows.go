//go:build windows

package native

import (
	"context"

	"github.com/go-ole/go-ole"
	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	adapter "github.com/rubyattack3r/remoteexec/internal/exec/windows/technique"
)

// NativeSession implements the adapter.Session primitives by calling Win32
// and COM directly from the host remoteexec runs on.
type NativeSession struct {
	target  string
	creds   credentials.Credentials
	auth    engine.Auth
	runtime engine.RuntimeOptions
	ident   identity
}

// NewSession resolves the identity for the requested auth mode. With
// AuthCredential the supplied credentials become an impersonation token;
// with AuthToken the process identity is used and no secret is handled.
func NewSession(target string, creds credentials.Credentials, auth engine.Auth, runtime engine.RuntimeOptions) (adapter.Session, error) {
	session := &NativeSession{target: target, creds: creds, auth: auth, runtime: runtime}
	switch auth {
	case engine.AuthToken, "":
		if creds.Username != "" || creds.Password != "" {
			return nil, errs.New(errs.Validation, "token auth takes no identity")
		}
	case engine.AuthCredential:
		ident, err := logon(creds)
		if err != nil {
			return nil, err
		}
		session.ident = ident
	default:
		return nil, errs.New(errs.Validation, "unsupported auth mode %q", auth)
	}
	return session, nil
}

// Close releases the impersonation token.
func (s *NativeSession) Close() {
	s.ident.close()
}

func (s *NativeSession) WriteFile(ctx context.Context, path string, content []byte) (string, error) {
	return writeFile(ctx, s.target, path, content, s.ident)
}

func (s *NativeSession) ReadFile(ctx context.Context, path string) ([]byte, error) {
	return readFile(ctx, s.target, path, s.ident)
}

func (s *NativeSession) RemoveFile(ctx context.Context, path string) error {
	if err := removeFile(ctx, s.target, path, s.ident); err != nil {
		return err
	}
	exists, err := s.FileExists(ctx, path)
	if err != nil {
		return err
	}
	if exists {
		return errs.New(errs.Cleanup, "%s still present after removal", path)
	}
	return nil
}

func (s *NativeSession) FileExists(ctx context.Context, path string) (bool, error) {
	return fileExists(ctx, s.target, path, s.ident)
}

func (s *NativeSession) Glob(ctx context.Context, pattern string) ([]string, error) {
	return globFiles(ctx, s.target, pattern, s.ident)
}

func (s *NativeSession) ProcessCreate(ctx context.Context, commandLine string) (uint32, error) {
	services, cleanup, err := wmiServices(s.target, `root\cimv2`, s.creds, s.auth)
	if err != nil {
		return 0, err
	}
	defer cleanup()
	return wmiProcessCreate(services, commandLine)
}

func (s *NativeSession) ProcessStart(ctx context.Context, path, args string) (uint32, error) {
	user, domain, password := comIdentity(s.creds, s.auth)
	commandLine := `"` + path + `"`
	if args != "" {
		commandLine += " " + args
	}
	if err := wsmanCommand(ctx, s.target, user, domain, password, commandLine, s.runtime.WinRMPort, s.runtime.WinRMHTTPS); err != nil {
		return 0, err
	}
	return 0, nil
}

func (s *NativeSession) ShellExecute(ctx context.Context, path, args string) error {
	user, domain, password := comIdentity(s.creds, s.auth)
	return s.ident.run(func() error { return shellExecuteRemote(s.target, path, args, user, domain, password) })
}

func (s *NativeSession) ShellAvailable(ctx context.Context) error {
	user, domain, password := comIdentity(s.creds, s.auth)
	return s.ident.run(func() error { return shellAvailableRemote(s.target, user, domain, password) })
}

func (s *NativeSession) ProcessFind(ctx context.Context, imageName, commandLineContains string) ([]uint32, error) {
	services, cleanup, err := wmiServices(s.target, `root\cimv2`, s.creds, s.auth)
	if err != nil {
		return nil, err
	}
	defer cleanup()
	return wmiProcessFind(services, imageName, commandLineContains)
}

func (s *NativeSession) ProcessExists(ctx context.Context, pid uint32) (bool, error) {
	pids, err := s.ProcessFind(ctx, "", "")
	if err != nil {
		return false, err
	}
	for _, candidate := range pids {
		if candidate == pid {
			return true, nil
		}
	}
	return false, nil
}

func (s *NativeSession) ProcessImage(ctx context.Context, pid uint32) (string, error) {
	services, cleanup, err := wmiServices(s.target, `root\cimv2`, s.creds, s.auth)
	if err != nil {
		return "", err
	}
	defer cleanup()
	return wmiProcessImage(services, pid)
}

func (s *NativeSession) ServiceGet(ctx context.Context, name string) (adapter.ServiceConfig, error) {
	var config adapter.ServiceConfig
	var getErr error
	s.ident.run(func() error {
		scm, err := openSCManager(s.target)
		if err != nil {
			getErr = err
			return nil
		}
		defer closeService(scm)
		config, getErr = scmQueryConfig(scm, name)
		return nil
	})
	return config, getErr
}

func (s *NativeSession) ServiceExists(ctx context.Context, name string) (bool, error) {
	var exists bool
	var existsErr error
	s.ident.run(func() error {
		scm, err := openSCManager(s.target)
		if err != nil {
			existsErr = err
			return nil
		}
		defer closeService(scm)
		exists, existsErr = scmServiceExists(scm, name)
		return nil
	})
	return exists, existsErr
}

func (s *NativeSession) ServiceCreate(ctx context.Context, name, pathName string) error {
	var createErr error
	s.ident.run(func() error {
		scm, err := openSCManager(s.target)
		if err != nil {
			createErr = err
			return nil
		}
		defer closeService(scm)
		createErr = scmCreateService(scm, name, pathName)
		return nil
	})
	return createErr
}

func (s *NativeSession) ServiceDelete(ctx context.Context, name string) error {
	var deleteErr error
	s.ident.run(func() error {
		scm, err := openSCManager(s.target)
		if err != nil {
			deleteErr = err
			return nil
		}
		defer closeService(scm)
		deleteErr = scmDeleteService(scm, name)
		return nil
	})
	return deleteErr
}

func (s *NativeSession) ServiceChangePath(ctx context.Context, name, pathName string, mechanism adapter.Mechanism) error {
	switch mechanism {
	case adapter.MechanismSCM:
		var changeErr error
		s.ident.run(func() error {
			scm, err := openSCManager(s.target)
			if err != nil {
				changeErr = err
				return nil
			}
			defer closeService(scm)
			changeErr = scmChangePath(scm, name, pathName)
			return nil
		})
		return changeErr
	case adapter.MechanismWMI:
		services, cleanup, err := wmiServices(s.target, `root\cimv2`, s.creds, s.auth)
		if err != nil {
			return err
		}
		defer cleanup()
		return wmiServiceChangePath(services, name, pathName)
	}
	return errs.New(errs.Validation, "unsupported service mechanism %q", mechanism)
}

func (s *NativeSession) ServiceStart(ctx context.Context, name string, mechanism adapter.Mechanism) error {
	switch mechanism {
	case adapter.MechanismSCM:
		var startErr error
		s.ident.run(func() error {
			scm, err := openSCManager(s.target)
			if err != nil {
				startErr = err
				return nil
			}
			defer closeService(scm)
			startErr = scmStart(scm, name)
			return nil
		})
		return startErr
	case adapter.MechanismWMI:
		services, cleanup, err := wmiServices(s.target, `root\cimv2`, s.creds, s.auth)
		if err != nil {
			return err
		}
		defer cleanup()
		return wmiServiceMethod(services, name, "StartService", map[int64]bool{0: true, 10: true})
	}
	return errs.New(errs.Validation, "unsupported service mechanism %q", mechanism)
}

func (s *NativeSession) ServiceStop(ctx context.Context, name string, mechanism adapter.Mechanism) error {
	switch mechanism {
	case adapter.MechanismSCM:
		var stopErr error
		s.ident.run(func() error {
			scm, err := openSCManager(s.target)
			if err != nil {
				stopErr = err
				return nil
			}
			defer closeService(scm)
			stopErr = scmStop(scm, name)
			return nil
		})
		return stopErr
	case adapter.MechanismWMI:
		services, cleanup, err := wmiServices(s.target, `root\cimv2`, s.creds, s.auth)
		if err != nil {
			return err
		}
		defer cleanup()
		return wmiServiceMethod(services, name, "StopService", map[int64]bool{0: true, 6: true})
	}
	return errs.New(errs.Validation, "unsupported service mechanism %q", mechanism)
}

func (s *NativeSession) taskSession() (*ole.IDispatch, *ole.IDispatch, func(), error) {
	user, domain, password := comIdentity(s.creds, s.auth)
	return taskService(s.target, user, domain, password)
}

func (s *NativeSession) TaskCreate(ctx context.Context, name, path, args string) error {
	svc, folder, cleanup, err := s.taskSession()
	if err != nil {
		return err
	}
	defer cleanup()
	return taskCreate(svc, folder, name, path, args)
}

func (s *NativeSession) TaskRun(ctx context.Context, name string) error {
	_, folder, cleanup, err := s.taskSession()
	if err != nil {
		return err
	}
	defer cleanup()
	return taskRun(folder, name)
}

func (s *NativeSession) TaskDelete(ctx context.Context, name string) error {
	_, folder, cleanup, err := s.taskSession()
	if err != nil {
		return err
	}
	defer cleanup()
	return taskDelete(folder, name)
}

func (s *NativeSession) TaskExists(ctx context.Context, name string) (bool, error) {
	_, folder, cleanup, err := s.taskSession()
	if err != nil {
		return false, err
	}
	defer cleanup()
	return taskExists(folder, name), nil
}

func (s *NativeSession) providerServices() (*ole.IDispatch, func(), error) {
	return wmiServices(s.target, `root\default`, s.creds, s.auth)
}

func (s *NativeSession) ProviderRegister(ctx context.Context, name, clsid string) error {
	services, cleanup, err := s.providerServices()
	if err != nil {
		return err
	}
	defer cleanup()
	return wmiProviderRegister(services, name, clsid)
}

func (s *NativeSession) ProviderDelete(ctx context.Context, name string) error {
	services, cleanup, err := s.providerServices()
	if err != nil {
		return err
	}
	defer cleanup()
	return wmiProviderDelete(services, name)
}

func (s *NativeSession) ProviderExists(ctx context.Context, name string) (bool, error) {
	services, cleanup, err := s.providerServices()
	if err != nil {
		return false, err
	}
	defer cleanup()
	return wmiProviderExists(services, name)
}

func (s *NativeSession) ProviderCOMRegister(ctx context.Context, clsid, dllPath string) error {
	services, cleanup, err := s.providerServices()
	if err != nil {
		return err
	}
	defer cleanup()
	return wmiProviderCOMRegister(services, clsid, dllPath)
}

func (s *NativeSession) ProviderCOMDelete(ctx context.Context, clsid string) error {
	services, cleanup, err := s.providerServices()
	if err != nil {
		return err
	}
	defer cleanup()
	return wmiProviderCOMDelete(services, clsid)
}

func (s *NativeSession) ProviderCOMExists(ctx context.Context, clsid string) (bool, error) {
	services, cleanup, err := s.providerServices()
	if err != nil {
		return false, err
	}
	defer cleanup()
	return wmiProviderCOMExists(services, clsid)
}

func (s *NativeSession) ProviderLoad(ctx context.Context, namespace, name string) error {
	services, cleanup, err := wmiServices(s.target, `root\cimv2`, s.creds, s.auth)
	if err != nil {
		return err
	}
	defer cleanup()
	return wmiProviderLoad(services, namespace, name)
}

func (s *NativeSession) ProviderUnload(ctx context.Context, namespace, name string) error {
	services, cleanup, err := wmiServices(s.target, `root\cimv2`, s.creds, s.auth)
	if err != nil {
		return err
	}
	defer cleanup()
	return wmiProviderUnload(services, namespace, name)
}
