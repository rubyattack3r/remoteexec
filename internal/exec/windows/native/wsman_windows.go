//go:build windows

package native

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	"golang.org/x/sys/windows"
)

const (
	shellResourceURI    = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
	wsmanCallbackEnd    = 0x1
	wsmanWaitIntervalMS = 100
	wsmanDefaultAuth    = 0
)

var (
	modWSMan                 = windows.NewLazySystemDLL("WsmSvc.dll")
	procWSManInitialize      = modWSMan.NewProc("WSManInitialize")
	procWSManDeinitialize    = modWSMan.NewProc("WSManDeinitialize")
	procWSManCreateSession   = modWSMan.NewProc("WSManCreateSession")
	procWSManCloseSession    = modWSMan.NewProc("WSManCloseSession")
	procWSManCreateShell     = modWSMan.NewProc("WSManCreateShell")
	procWSManRunShellCommand = modWSMan.NewProc("WSManRunShellCommand")
	procWSManCloseCommand    = modWSMan.NewProc("WSManCloseCommand")
	procWSManCloseShell      = modWSMan.NewProc("WSManCloseShell")
	procRtlMoveMemory        = windows.NewLazySystemDLL("ntdll.dll").NewProc("RtlMoveMemory")
	wsmanCallback            = windows.NewCallback(wsmanCompletion)
	wsmanOperations          sync.Map
)

type wsmanUsernamePassword struct {
	username *uint16
	password *uint16
}

type wsmanAuthenticationCredentials struct {
	mechanism uint32
	account   wsmanUsernamePassword
}

type wsmanError struct {
	code        uint32
	errorDetail *uint16
	language    *uint16
	machineName *uint16
	pluginName  *uint16
}

type wsmanShellAsync struct {
	operationContext uintptr
	completion       uintptr
}

type wsmanOperation struct {
	event  windows.Handle
	code   uint32
	detail string
}

func newWSManOperation() (*wsmanOperation, wsmanShellAsync, error) {
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, wsmanShellAsync{}, errs.Wrap(errs.Execution, err)
	}
	op := &wsmanOperation{event: event}
	wsmanOperations.Store(uintptr(event), op)
	return op, wsmanShellAsync{operationContext: uintptr(event), completion: wsmanCallback}, nil
}

func (op *wsmanOperation) close() {
	wsmanOperations.Delete(uintptr(op.event))
	_ = windows.CloseHandle(op.event)
}

func (op *wsmanOperation) wait(ctx context.Context, operation string) error {
	for {
		status, err := windows.WaitForSingleObject(op.event, wsmanWaitIntervalMS)
		if err != nil {
			return errs.Wrap(errs.Execution, err)
		}
		switch status {
		case windows.WAIT_OBJECT_0:
			if op.code != 0 {
				if op.detail != "" {
					return errs.New(errs.Execution, "%s failed (code %d): %s", operation, op.code, op.detail)
				}
				return errs.New(errs.Execution, "%s failed (code %d)", operation, op.code)
			}
			return nil
		case uint32(windows.WAIT_TIMEOUT):
			// The native stack retains the callback context until completion;
			// continue waiting safely, then report any caller cancellation.
			continue
		default:
			return errs.New(errs.Execution, "%s wait returned status 0x%x", operation, status)
		}
	}
}

func wsmanCompletion(operationContext, flags, errorPointer, _, _, _, _ uintptr) uintptr {
	value, ok := wsmanOperations.Load(operationContext)
	if !ok {
		return 0
	}
	op := value.(*wsmanOperation)
	if errorPointer != 0 {
		var apiError wsmanError
		procRtlMoveMemory.Call(
			uintptr(unsafe.Pointer(&apiError)), errorPointer, unsafe.Sizeof(apiError),
		)
		op.code = apiError.code
		if apiError.errorDetail != nil {
			op.detail = windows.UTF16PtrToString(apiError.errorDetail)
		}
	}
	if flags&wsmanCallbackEnd != 0 || op.code != 0 {
		_ = windows.SetEvent(op.event)
	}
	return 0
}

func callWSManAsync(ctx context.Context, operation string, invoke func(*wsmanShellAsync)) error {
	op, async, err := newWSManOperation()
	if err != nil {
		return err
	}
	defer op.close()
	invoke(&async)
	runtime.KeepAlive(async)
	if err := op.wait(ctx, operation); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	return nil
}

// wsmanCommand creates a native WinRM command shell and dispatches commandLine
// with WSManRunShellCommand. Every native handle is closed in reverse order.
func wsmanCommand(ctx context.Context, target, user, domain, password, commandLine string, port int, useHTTPS bool) error {
	var api uintptr
	if code, _, _ := procWSManInitialize.Call(0, uintptr(unsafe.Pointer(&api))); code != 0 {
		return errs.New(errs.Execution, "WSManInitialize failed (code %d)", code)
	}
	defer procWSManDeinitialize.Call(api, 0)

	if port == 0 {
		port = engine.DefaultWinRMHTTPPort
		if useHTTPS {
			port = engine.DefaultWinRMHTTPSPort
		}
	}
	scheme := "http"
	if useHTTPS {
		scheme = "https"
	}
	connection, err := windows.UTF16PtrFromString(fmt.Sprintf("%s://%s:%d/wsman", scheme, target, port))
	if err != nil {
		return errs.New(errs.Validation, "invalid WSMan target %q: %v", target, err)
	}
	var credentialsPointer uintptr
	var credentials wsmanAuthenticationCredentials
	var usernamePointer, passwordPointer *uint16
	if user != "" {
		account := user
		if domain != "" && !strings.ContainsAny(user, `\\@`) {
			account = domain + `\` + user
		}
		usernamePointer, err = windows.UTF16PtrFromString(account)
		if err != nil {
			return errs.New(errs.Validation, "invalid WSMan username: %v", err)
		}
		passwordPointer, err = windows.UTF16PtrFromString(password)
		if err != nil {
			return errs.New(errs.Validation, "invalid WSMan password: %v", err)
		}
		credentials = wsmanAuthenticationCredentials{
			mechanism: wsmanDefaultAuth,
			account:   wsmanUsernamePassword{username: usernamePointer, password: passwordPointer},
		}
		credentialsPointer = uintptr(unsafe.Pointer(&credentials))
	}

	var session uintptr
	if code, _, _ := procWSManCreateSession.Call(
		api, uintptr(unsafe.Pointer(connection)), 0, credentialsPointer, 0,
		uintptr(unsafe.Pointer(&session)),
	); code != 0 {
		return errs.New(errs.Reachability, "WSManCreateSession to %s failed (code %d)", target, code)
	}
	runtime.KeepAlive(credentials)
	runtime.KeepAlive(usernamePointer)
	runtime.KeepAlive(passwordPointer)
	defer procWSManCloseSession.Call(session, 0)

	resourceURI, _ := windows.UTF16PtrFromString(shellResourceURI)
	var shell uintptr
	if err := callWSManAsync(ctx, "WSManCreateShell", func(async *wsmanShellAsync) {
		procWSManCreateShell.Call(
			session, 0, uintptr(unsafe.Pointer(resourceURI)), 0, 0, 0,
			uintptr(unsafe.Pointer(async)), uintptr(unsafe.Pointer(&shell)),
		)
	}); err != nil {
		return err
	}
	defer func() {
		_ = callWSManAsync(context.Background(), "WSManCloseShell", func(async *wsmanShellAsync) {
			procWSManCloseShell.Call(shell, 0, uintptr(unsafe.Pointer(async)))
		})
	}()

	commandLinePointer, err := windows.UTF16PtrFromString(commandLine)
	if err != nil {
		return errs.New(errs.Validation, "invalid WSMan command line: %v", err)
	}
	var command uintptr
	if err := callWSManAsync(ctx, "WSManRunShellCommand", func(async *wsmanShellAsync) {
		procWSManRunShellCommand.Call(
			shell, 0, uintptr(unsafe.Pointer(commandLinePointer)), 0, 0,
			uintptr(unsafe.Pointer(async)), uintptr(unsafe.Pointer(&command)),
		)
	}); err != nil {
		return err
	}
	defer func() {
		_ = callWSManAsync(context.Background(), "WSManCloseCommand", func(async *wsmanShellAsync) {
			procWSManCloseCommand.Call(command, 0, uintptr(unsafe.Pointer(async)))
		})
	}()
	runtime.KeepAlive(commandLinePointer)
	return nil
}
