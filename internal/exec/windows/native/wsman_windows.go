//go:build windows

package native

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"
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
	wsmanDataDWORD      = 4
	wsmanOptionTimeout  = 1
)

var (
	modWSMan                 = windows.NewLazySystemDLL("WsmSvc.dll")
	procWSManInitialize      = modWSMan.NewProc("WSManInitialize")
	procWSManDeinitialize    = modWSMan.NewProc("WSManDeinitialize")
	procWSManCreateSession   = modWSMan.NewProc("WSManCreateSession")
	procWSManSetSessionOpt   = modWSMan.NewProc("WSManSetSessionOption")
	procWSManCloseSession    = modWSMan.NewProc("WSManCloseSession")
	procWSManCreateShell     = modWSMan.NewProc("WSManCreateShell")
	procWSManRunShellCommand = modWSMan.NewProc("WSManRunShellCommand")
	procWSManReceiveOutput   = modWSMan.NewProc("WSManReceiveShellOutput")
	procWSManCloseOperation  = modWSMan.NewProc("WSManCloseOperation")
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

// wsmanData mirrors WSMAN_DATA. Its anonymous union is two pointer-sized
// words on both supported Windows architectures.
type wsmanData struct {
	kind  uint32
	value [2]uintptr
}

type wsmanReceiveDataResult struct {
	streamID     *uint16
	streamData   wsmanData
	commandState *uint16
	exitCode     uint32
}

type wsmanOperation struct {
	event           windows.Handle
	code            uint32
	detail          string
	receive         bool
	commandDone     bool
	commandExitCode uint32
}

func newWSManOperation(receive bool) (*wsmanOperation, wsmanShellAsync, error) {
	event, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return nil, wsmanShellAsync{}, errs.Wrap(errs.Execution, err)
	}
	op := &wsmanOperation{event: event, receive: receive}
	wsmanOperations.Store(uintptr(event), op)
	return op, wsmanShellAsync{operationContext: uintptr(event), completion: wsmanCallback}, nil
}

func (op *wsmanOperation) close() {
	wsmanOperations.Delete(uintptr(op.event))
	_ = windows.CloseHandle(op.event)
}

func (op *wsmanOperation) wait(ctx context.Context, operation string, cancel func()) error {
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
			if err := ctx.Err(); err != nil && cancel != nil {
				cancel()
				return errs.Wrap(errs.Execution, err)
			}
			// The native stack retains the callback context until completion;
			// continue waiting safely, then report any caller cancellation.
			continue
		default:
			return errs.New(errs.Execution, "%s wait returned status 0x%x", operation, status)
		}
	}
}

func wsmanCompletion(operationContext, flags, errorPointer, _, _, _, dataPointer uintptr) uintptr {
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
	if op.receive && dataPointer != 0 {
		var data wsmanReceiveDataResult
		procRtlMoveMemory.Call(
			uintptr(unsafe.Pointer(&data)), dataPointer, unsafe.Sizeof(data),
		)
		if data.commandState != nil && strings.HasSuffix(
			windows.UTF16PtrToString(data.commandState), "/CommandState/Done",
		) {
			op.commandDone = true
			op.commandExitCode = data.exitCode
		}
	}
	if flags&wsmanCallbackEnd != 0 || op.code != 0 || op.commandDone {
		_ = windows.SetEvent(op.event)
	}
	return 0
}

func callWSManAsync(ctx context.Context, operation string, invoke func(*wsmanShellAsync)) error {
	op, async, err := newWSManOperation(false)
	if err != nil {
		return err
	}
	defer op.close()
	invoke(&async)
	runtime.KeepAlive(async)
	if err := op.wait(ctx, operation, nil); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	return nil
}

func receiveWSManCommand(ctx context.Context, shell, command uintptr) error {
	op, async, err := newWSManOperation(true)
	if err != nil {
		return err
	}
	defer op.close()

	var receiveOperation uintptr
	procWSManReceiveOutput.Call(
		shell, command, 0, 0, uintptr(unsafe.Pointer(&async)),
		uintptr(unsafe.Pointer(&receiveOperation)),
	)
	runtime.KeepAlive(async)
	operationClosed := false
	closeOperation := func() {
		if receiveOperation != 0 && !operationClosed {
			procWSManCloseOperation.Call(receiveOperation, 0)
			operationClosed = true
		}
	}
	defer closeOperation()
	if err := op.wait(ctx, "WSManReceiveShellOutput", closeOperation); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	if !op.commandDone {
		return errs.New(errs.Execution, "WSMan command ended without a completion state")
	}
	if op.commandExitCode != 0 {
		return errs.New(errs.Execution, "WSMan command exited with code %d", op.commandExitCode)
	}
	return nil
}

func setWSManSessionTimeout(ctx context.Context, session uintptr) error {
	deadline, ok := ctx.Deadline()
	if !ok {
		return nil
	}
	remaining := time.Until(deadline)
	if remaining <= 0 {
		return errs.Wrap(errs.Execution, context.DeadlineExceeded)
	}
	milliseconds := remaining.Milliseconds()
	if milliseconds < 1 {
		milliseconds = 1
	}
	if milliseconds > int64(4294967295) {
		milliseconds = int64(4294967295)
	}
	data := wsmanData{kind: wsmanDataDWORD}
	data.value[0] = uintptr(uint32(milliseconds))
	if code, _, _ := procWSManSetSessionOpt.Call(
		session, wsmanOptionTimeout, uintptr(unsafe.Pointer(&data)),
	); code != 0 {
		return errs.New(errs.Execution, "WSManSetSessionOption timeout failed (code %d)", code)
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
	if err := setWSManSessionTimeout(ctx, session); err != nil {
		return err
	}

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
	return receiveWSManCommand(ctx, shell, command)
}
