//go:build windows

package native

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"golang.org/x/sys/windows"
)

func taskService(target, user, domain, password string) (*ole.IDispatch, *ole.IDispatch, func(), error) {
	svc, cleanup, err := comDispatch("Schedule.Service")
	if err != nil {
		return nil, nil, nil, err
	}
	if _, err := oleutil.CallMethod(svc, "Connect", target, user, domain, password); err != nil {
		cleanup()
		return nil, nil, nil, errs.Wrap(errs.Authentication, fmt.Errorf("ITaskService.Connect to %s: %w", target, err))
	}
	folderRaw, err := oleutil.CallMethod(svc, "GetFolder", `\`)
	if err != nil {
		cleanup()
		return nil, nil, nil, errs.Wrap(errs.Reachability, err)
	}
	folder := folderRaw.ToIDispatch()
	outer := func() {
		folder.Release()
		cleanup()
	}
	return svc, folder, outer, nil
}

func taskCreate(svc, folder *ole.IDispatch, name, exe, args string) error {
	definitionRaw, err := oleutil.CallMethod(svc, "NewTask", 0)
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	definition := definitionRaw.ToIDispatch()
	defer definition.Release()
	principal, err := oleutil.GetProperty(definition, "Principal")
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	if _, err := oleutil.PutProperty(principal.ToIDispatch(), "UserId", "SYSTEM"); err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	if _, err := oleutil.PutProperty(principal.ToIDispatch(), "LogonType", 5); err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	if _, err := oleutil.PutProperty(principal.ToIDispatch(), "RunLevel", 1); err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	principal.ToIDispatch().Release()
	actions, err := oleutil.GetProperty(definition, "Actions")
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	actionRaw, err := oleutil.CallMethod(actions.ToIDispatch(), "Create", 0)
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	action := actionRaw.ToIDispatch()
	if _, err := oleutil.PutProperty(action, "Path", exe); err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	if _, err := oleutil.PutProperty(action, "Arguments", args); err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	action.Release()
	actions.ToIDispatch().Release()
	// 6 = TASK_CREATE_OR_UPDATE, 5 = TASK_LOGON_SERVICE_ACCOUNT.
	registered, err := oleutil.CallMethod(folder, "RegisterTaskDefinition", name, definition, 6, "SYSTEM", nil, 5)
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	registered.ToIDispatch().Release()
	return nil
}

func taskRun(folder *ole.IDispatch, name string) error {
	taskRaw, err := oleutil.CallMethod(folder, "GetTask", name)
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	task := taskRaw.ToIDispatch()
	defer task.Release()
	running, err := oleutil.CallMethod(task, "Run", nil)
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	running.Clear()
	return nil
}

func taskDelete(folder *ole.IDispatch, name string) error {
	if _, err := oleutil.CallMethod(folder, "DeleteTask", name, 0); err != nil {
		return errs.Wrap(errs.Cleanup, err)
	}
	return nil
}

func taskExists(folder *ole.IDispatch, name string) bool {
	raw, err := oleutil.CallMethod(folder, "GetTask", name)
	if err != nil {
		return false
	}
	raw.ToIDispatch().Release()
	return true
}

// shellWindowsCLSID is the out-of-process ShellWindows automation server.
// Its active Explorer window exposes Document.Application as IShellDispatch2.
const shellWindowsCLSID = "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}"

const (
	rpcAuthnWinNT           = 10
	rpcAuthzNone            = 0
	rpcAuthnLevelPktPrivacy = 6
	rpcImpersonate          = 3
	secIdentityUnicode      = 2
)

var (
	modole32              = windows.NewLazySystemDLL("ole32.dll")
	procCoCreateInstEx    = modole32.NewProc("CoCreateInstanceEx")
	procCoSetProxyBlanket = modole32.NewProc("CoSetProxyBlanket")
)

type serverInfo struct {
	reserved1 uint32
	name      *uint16
	authInfo  uintptr
	reserved2 uint32
}

type authIdentity struct {
	user           *uint16
	userLength     uint32
	domain         *uint16
	domainLength   uint32
	password       *uint16
	passwordLength uint32
	flags          uint32
}

type authInfo struct {
	authnService       uint32
	authzService       uint32
	serverPrincipal    *uint16
	authnLevel         uint32
	impersonationLevel uint32
	identity           *authIdentity
	capabilities       uint32
}

type multiQi struct {
	iid *ole.GUID
	itf unsafe.Pointer
	hr  uint32
}

func setProxyAuthentication(dispatch *ole.IDispatch, identity *authIdentity) error {
	if identity == nil {
		return nil
	}
	hr, _, _ := procCoSetProxyBlanket.Call(
		uintptr(unsafe.Pointer(dispatch)), rpcAuthnWinNT, rpcAuthzNone, 0,
		rpcAuthnLevelPktPrivacy, rpcImpersonate,
		uintptr(unsafe.Pointer(identity)), 0,
	)
	if uint32(hr) != 0 {
		return errs.New(errs.Authentication, "set DCOM proxy authentication failed (hr=0x%x)", uint32(hr))
	}
	return nil
}

// withRemoteShellApplication activates ShellWindows on the target through
// DCOM and resolves the active Explorer window's IShellDispatch2 interface.
// Resolving the interface is read-only and can therefore be used by preflight.
func withRemoteShellApplication(target, user, domain, password string, use func(*ole.IDispatch) error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err != nil {
		return errs.Wrap(errs.Execution, fmt.Errorf("initialize COM: %w", err))
	}
	defer ole.CoUninitialize()

	clsid := ole.NewGUID(shellWindowsCLSID)
	name, err := windows.UTF16PtrFromString(target)
	if err != nil {
		return errs.New(errs.Execution, "invalid target: %v", err)
	}
	qi := []multiQi{{iid: ole.IID_IDispatch}}
	info := serverInfo{name: name}
	var identity authIdentity
	var authentication authInfo
	var userUTF16, domainUTF16, passwordUTF16 []uint16
	if user != "" {
		userUTF16, err = windows.UTF16FromString(user)
		if err != nil {
			return errs.New(errs.Validation, "invalid DCOM username: %v", err)
		}
		domainUTF16, err = windows.UTF16FromString(domain)
		if err != nil {
			return errs.New(errs.Validation, "invalid DCOM domain: %v", err)
		}
		passwordUTF16, err = windows.UTF16FromString(password)
		if err != nil {
			return errs.New(errs.Validation, "invalid DCOM password: %v", err)
		}
		identity = authIdentity{
			user: &userUTF16[0], userLength: uint32(len(userUTF16) - 1),
			domain: &domainUTF16[0], domainLength: uint32(len(domainUTF16) - 1),
			password: &passwordUTF16[0], passwordLength: uint32(len(passwordUTF16) - 1),
			flags: secIdentityUnicode,
		}
		authentication = authInfo{
			authnService: rpcAuthnWinNT, authzService: rpcAuthzNone,
			authnLevel: rpcAuthnLevelPktPrivacy, impersonationLevel: rpcImpersonate,
			identity: &identity,
		}
		info.authInfo = uintptr(unsafe.Pointer(&authentication))
	}
	hr, _, _ := procCoCreateInstEx.Call(
		uintptr(unsafe.Pointer(clsid)),
		0,
		uintptr(ole.CLSCTX_REMOTE_SERVER),
		uintptr(unsafe.Pointer(&info)),
		1,
		uintptr(unsafe.Pointer(&qi[0])),
	)
	runtime.KeepAlive(userUTF16)
	runtime.KeepAlive(domainUTF16)
	runtime.KeepAlive(passwordUTF16)
	runtime.KeepAlive(authentication)
	if hr != 0 || qi[0].hr != 0 || qi[0].itf == nil {
		return errs.New(errs.Execution, "remote DCOM activation on %s failed (hr=0x%x qi.hr=0x%x)", target, hr, qi[0].hr)
	}
	windowsCollection := (*ole.IDispatch)(qi[0].itf)
	defer windowsCollection.Release()
	var proxyIdentity *authIdentity
	if user != "" {
		proxyIdentity = &identity
	}
	if err := setProxyAuthentication(windowsCollection, proxyIdentity); err != nil {
		return err
	}
	browserRaw, err := oleutil.CallMethod(windowsCollection, "Item")
	if err != nil {
		return errs.Wrap(errs.Execution, fmt.Errorf("resolve active ShellWindows item: %w", err))
	}
	browser := browserRaw.ToIDispatch()
	if browser == nil {
		return errs.New(errs.Execution, "active ShellWindows item did not expose IDispatch")
	}
	defer browser.Release()
	if err := setProxyAuthentication(browser, proxyIdentity); err != nil {
		return err
	}
	documentRaw, err := oleutil.GetProperty(browser, "Document")
	if err != nil {
		return errs.Wrap(errs.Execution, fmt.Errorf("resolve active shell document: %w", err))
	}
	document := documentRaw.ToIDispatch()
	if document == nil {
		return errs.New(errs.Execution, "active shell document did not expose IDispatch")
	}
	defer document.Release()
	if err := setProxyAuthentication(document, proxyIdentity); err != nil {
		return err
	}
	applicationRaw, err := oleutil.GetProperty(document, "Application")
	if err != nil {
		return errs.Wrap(errs.Execution, fmt.Errorf("resolve IShellDispatch2 application: %w", err))
	}
	application := applicationRaw.ToIDispatch()
	if application == nil {
		return errs.New(errs.Execution, "shell application did not expose IShellDispatch2")
	}
	defer application.Release()
	if err := setProxyAuthentication(application, proxyIdentity); err != nil {
		return err
	}
	return use(application)
}

func shellAvailableRemote(target, user, domain, password string) error {
	return withRemoteShellApplication(target, user, domain, password, func(*ole.IDispatch) error { return nil })
}

func shellExecuteRemote(target, exe, args, user, domain, password string) error {
	return withRemoteShellApplication(target, user, domain, password, func(application *ole.IDispatch) error {
		result, err := oleutil.CallMethod(application, "ShellExecute", exe, args, "", "open", 0)
		if err != nil {
			return errs.Wrap(errs.Execution, err)
		}
		result.Clear()
		return nil
	})
}
