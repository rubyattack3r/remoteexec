//go:build windows

package native

import (
	"fmt"
	"unsafe"

	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	adapter "github.com/rubyattack3r/remoteexec/internal/exec/windows/technique"
	"golang.org/x/sys/windows"
)

var (
	modadvapi32        = windows.NewLazySystemDLL("advapi32.dll")
	procOpenSCManagerW = modadvapi32.NewProc("OpenSCManagerW")
	procOpenServiceW   = modadvapi32.NewProc("OpenServiceW")
	procCloseSvcHandle = modadvapi32.NewProc("CloseServiceHandle")
	procQuerySvcCfg    = modadvapi32.NewProc("QueryServiceConfigW")
	procQuerySvcStat   = modadvapi32.NewProc("QueryServiceStatus")
	procChangeSvcCfg   = modadvapi32.NewProc("ChangeServiceConfigW")
	procStartServiceW  = modadvapi32.NewProc("StartServiceW")
	procControlService = modadvapi32.NewProc("ControlService")
	procCreateServiceW = modadvapi32.NewProc("CreateServiceW")
	procDeleteService  = modadvapi32.NewProc("DeleteService")
)

const serviceNoChange = 0xFFFFFFFF

type queryServiceConfigW struct {
	serviceType      uint32
	startType        uint32
	errorControl     uint32
	binaryPathName   *uint16
	loadOrderGroup   *uint16
	tagID            uint32
	dependencies     *uint16
	serviceStartName *uint16
	displayName      *uint16
}

type serviceStatus struct {
	serviceType, currentState, controlsAccepted, win32ExitCode, serviceSpecificExitCode, checkPoint, waitHint uint32
}

func openSCManager(target string) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(`\\` + target)
	if err != nil {
		return 0, errs.New(errs.Reachability, "invalid target: %v", err)
	}
	handle, _, callErr := procOpenSCManagerW.Call(uintptr(unsafe.Pointer(name)), 0, 0xF003F)
	if handle == 0 {
		return 0, errs.Wrap(errs.Reachability, callErr)
	}
	return windows.Handle(handle), nil
}

func openService(scm windows.Handle, name string, access uint32) (windows.Handle, error) {
	ptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, errs.New(errs.Validation, "invalid service name: %v", err)
	}
	handle, _, callErr := procOpenServiceW.Call(uintptr(scm), uintptr(unsafe.Pointer(ptr)), uintptr(access))
	if handle == 0 {
		return 0, errs.Wrap(errs.Reachability, callErr)
	}
	return windows.Handle(handle), nil
}

func closeService(handle windows.Handle) {
	procCloseSvcHandle.Call(uintptr(handle))
}

func scmServiceExists(scm windows.Handle, name string) (bool, error) {
	svc, err := openService(scm, name, 0x4)
	if err != nil {
		if isErrno(err, 1060) {
			return false, nil
		}
		if isErrno(err, 1072) {
			return true, nil
		}
		return false, err
	}
	closeService(svc)
	return true, nil
}

func scmCreateService(scm windows.Handle, name, path string) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return errs.New(errs.Validation, "invalid service name: %v", err)
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errs.New(errs.Validation, "invalid service path: %v", err)
	}
	handle, _, callErr := procCreateServiceW.Call(
		uintptr(scm), uintptr(unsafe.Pointer(namePtr)), uintptr(unsafe.Pointer(namePtr)),
		0xF01FF, 0x10, 0x3, 0x1, uintptr(unsafe.Pointer(pathPtr)),
		0, 0, 0, 0, 0,
	)
	if handle == 0 {
		return errs.Wrap(errs.Execution, fmt.Errorf("CreateServiceW: %w", callErr))
	}
	closeService(windows.Handle(handle))
	return nil
}

func scmDeleteService(scm windows.Handle, name string) error {
	svc, err := openService(scm, name, 0x10000)
	if err != nil {
		if isErrno(err, 1060) {
			return nil
		}
		return err
	}
	defer closeService(svc)
	r, _, callErr := procDeleteService.Call(uintptr(svc))
	if r == 0 && !isErrno(callErr, 1072) {
		return errs.Wrap(errs.Cleanup, fmt.Errorf("DeleteService: %w", callErr))
	}
	return nil
}

func scmQueryConfig(scm windows.Handle, name string) (adapter.ServiceConfig, error) {
	var config adapter.ServiceConfig
	svc, err := openService(scm, name, 0x1|0x4)
	if err != nil {
		return config, err
	}
	defer closeService(svc)
	var needed uint32
	_, _, _ = procQuerySvcCfg.Call(uintptr(svc), 0, 0, uintptr(unsafe.Pointer(&needed)))
	if needed == 0 {
		return config, errs.New(errs.Reachability, "query of %s returned no configuration", name)
	}
	buf := make([]byte, needed)
	if r, _, callErr := procQuerySvcCfg.Call(uintptr(svc), uintptr(unsafe.Pointer(&buf[0])), uintptr(needed), uintptr(unsafe.Pointer(&needed))); r == 0 {
		return config, errs.Wrap(errs.Reachability, callErr)
	}
	cfg := (*queryServiceConfigW)(unsafe.Pointer(&buf[0]))
	var status serviceStatus
	if r, _, callErr := procQuerySvcStat.Call(uintptr(svc), uintptr(unsafe.Pointer(&status))); r == 0 {
		return config, errs.Wrap(errs.Reachability, callErr)
	}
	config.Name = name
	config.PathName = windows.UTF16PtrToString(cfg.binaryPathName)
	config.DisplayName = windows.UTF16PtrToString(cfg.displayName)
	config.StartName = windows.UTF16PtrToString(cfg.serviceStartName)
	switch cfg.startType {
	case 2:
		config.StartMode = "Auto"
	case 3:
		config.StartMode = "Manual"
	case 4:
		config.StartMode = "Disabled"
	default:
		config.StartMode = "Unknown"
	}
	switch status.currentState {
	case 1:
		config.State = "Stopped"
	case 2:
		config.State = "Start Pending"
	case 3:
		config.State = "Stop Pending"
	case 4:
		config.State = "Running"
	default:
		config.State = "Unknown"
	}
	config.DesktopInteract = cfg.serviceType&0x100 != 0
	return config, nil
}

func scmChangePath(scm windows.Handle, name, path string) error {
	svc, err := openService(scm, name, 0x2)
	if err != nil {
		return err
	}
	defer closeService(svc)
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return errs.New(errs.Validation, "invalid path: %v", err)
	}
	r, _, callErr := procChangeSvcCfg.Call(
		uintptr(svc), serviceNoChange, serviceNoChange, serviceNoChange,
		uintptr(unsafe.Pointer(pathPtr)), 0, 0, 0, 0, 0, 0,
	)
	if r == 0 {
		return errs.Wrap(errs.Execution, fmt.Errorf("ChangeServiceConfigW: %w", callErr))
	}
	return nil
}

func scmStart(scm windows.Handle, name string) error {
	const serviceStartAndQueryStatus = 0x10 | 0x4
	svc, err := openService(scm, name, serviceStartAndQueryStatus)
	if err != nil {
		return err
	}
	defer closeService(svc)
	r, _, callErr := procStartServiceW.Call(uintptr(svc), 0, 0)
	if r == 0 && !isErrno(callErr, 1056) {
		return errs.Wrap(errs.Execution, fmt.Errorf("StartServiceW: %w", callErr))
	}
	return nil
}

func scmStop(scm windows.Handle, name string) error {
	const serviceStopAndQueryStatus = 0x20 | 0x4
	svc, err := openService(scm, name, serviceStopAndQueryStatus)
	if err != nil {
		return err
	}
	defer closeService(svc)
	var status serviceStatus
	r, _, callErr := procControlService.Call(uintptr(svc), 1, uintptr(unsafe.Pointer(&status)))
	if r == 0 && !isErrno(callErr, 1062) {
		return errs.Wrap(errs.Execution, fmt.Errorf("ControlService: %w", callErr))
	}
	return nil
}
