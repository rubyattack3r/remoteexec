//go:build windows

package native

import (
	"fmt"
	"runtime"
	"strings"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"github.com/rubyattack3r/remoteexec/internal/exec/credentials"
	"github.com/rubyattack3r/remoteexec/internal/exec/engine"
	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
)

// comDispatch instantiates a COM class by program identifier and returns a
// cleanup function that must be called from the same goroutine.
func comDispatch(progID string) (*ole.IDispatch, func(), error) {
	runtime.LockOSThread()
	// Already-initialized results (S_FALSE) are acceptable; genuine failures
	// surface on the next COM call with a clearer error.
	_ = ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)
	unknown, err := oleutil.CreateObject(progID)
	if err != nil {
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, errs.Wrap(errs.Execution, fmt.Errorf("create %s: %w", progID, err))
	}
	dispatch, err := unknown.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		unknown.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
		return nil, nil, errs.Wrap(errs.Execution, fmt.Errorf("query %s: %w", progID, err))
	}
	cleanup := func() {
		dispatch.Release()
		unknown.Release()
		ole.CoUninitialize()
		runtime.UnlockOSThread()
	}
	return dispatch, cleanup, nil
}

func wqlEscape(value string) string {
	return strings.ReplaceAll(value, "'", "''")
}

func wmiServices(target, namespace string, creds credentials.Credentials, auth engine.Auth) (*ole.IDispatch, func(), error) {
	locator, cleanup, err := comDispatch("WbemScripting.SWbemLocator")
	if err != nil {
		return nil, nil, err
	}
	user, domain, password := comIdentity(creds, auth)
	if domain != "" {
		user = domain + "\\" + user
	}
	servicesRaw, err := oleutil.CallMethod(locator, "ConnectServer", target, namespace, user, password)
	if err != nil {
		cleanup()
		return nil, nil, errs.Wrap(errs.Authentication, fmt.Errorf("ConnectServer to %s: %w", target, err))
	}
	services := servicesRaw.ToIDispatch()
	outer := func() {
		services.Release()
		cleanup()
	}
	return services, outer, nil
}

func wmiProcessCreate(services *ole.IDispatch, commandLine string) (uint32, error) {
	result, err := wmiExecMethod(services, "Win32_Process", "Create", map[string]any{"CommandLine": commandLine})
	if err != nil {
		return 0, err
	}
	defer result.Release()
	returnValue, err := oleutil.GetProperty(result, "ReturnValue")
	if err != nil {
		return 0, errs.Wrap(errs.Execution, err)
	}
	if returnValue.Val != 0 {
		return 0, errs.New(errs.Execution, "Win32_Process.Create returned %d", returnValue.Val)
	}
	pidValue, err := oleutil.GetProperty(result, "ProcessId")
	if err != nil {
		return 0, errs.Wrap(errs.Execution, err)
	}
	return uint32(pidValue.Val), nil
}

// wmiProcessFind returns the process ids of image whose command line
// contains the needle (empty needle matches every instance of the image).
func wmiProcessFind(services *ole.IDispatch, image, needle string) ([]uint32, error) {
	wql := "SELECT ProcessId, CommandLine FROM Win32_Process"
	if image != "" {
		wql += fmt.Sprintf(" WHERE Name='%s'", wqlEscape(image))
	}
	raw, err := oleutil.CallMethod(services, "ExecQuery", wql)
	if err != nil {
		return nil, errs.Wrap(errs.Execution, err)
	}
	query := raw.ToIDispatch()
	defer query.Release()
	var pids []uint32
	err = oleutil.ForEach(query, func(v *ole.VARIANT) error {
		item := v.ToIDispatch()
		defer item.Release()
		if needle != "" {
			commandLine, err := oleutil.GetProperty(item, "CommandLine")
			if err != nil {
				return nil
			}
			if !strings.Contains(commandLine.ToString(), needle) {
				return nil
			}
		}
		pidValue, err := oleutil.GetProperty(item, "ProcessId")
		if err != nil {
			return nil
		}
		pids = append(pids, uint32(pidValue.Val))
		return nil
	})
	if err != nil {
		return nil, errs.Wrap(errs.Execution, err)
	}
	return pids, nil
}

func wmiProcessImage(services *ole.IDispatch, pid uint32) (string, error) {
	wql := fmt.Sprintf("SELECT ExecutablePath FROM Win32_Process WHERE ProcessId=%d", pid)
	raw, err := oleutil.CallMethod(services, "ExecQuery", wql)
	if err != nil {
		return "", errs.Wrap(errs.Execution, err)
	}
	query := raw.ToIDispatch()
	defer query.Release()
	image := ""
	err = oleutil.ForEach(query, func(v *ole.VARIANT) error {
		item := v.ToIDispatch()
		defer item.Release()
		value, err := oleutil.GetProperty(item, "ExecutablePath")
		if err == nil {
			image = value.ToString()
		}
		return nil
	})
	if err != nil {
		return "", errs.Wrap(errs.Execution, err)
	}
	if image == "" {
		return "", errs.New(errs.Validation, "process id %d has no readable executable path", pid)
	}
	return image, nil
}

func wmiServiceObject(services *ole.IDispatch, name string) (*ole.IDispatch, func(), error) {
	raw, err := oleutil.CallMethod(services, "Get", fmt.Sprintf("Win32_Service.Name='%s'", wqlEscape(name)))
	if err != nil {
		return nil, nil, errs.Wrap(errs.Reachability, fmt.Errorf("service %s: %w", name, err))
	}
	dispatch := raw.ToIDispatch()
	return dispatch, func() { dispatch.Release() }, nil
}

func wmiServiceChangePath(services *ole.IDispatch, name, path string) error {
	result, err := wmiExecMethod(services, wmiServicePath(name), "Change", map[string]any{"PathName": path})
	if err != nil {
		return err
	}
	defer result.Release()
	returnValue, err := oleutil.GetProperty(result, "ReturnValue")
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	if returnValue.Val != 0 {
		return errs.New(errs.Execution, "Win32_Service.Change returned %d", returnValue.Val)
	}
	return nil
}

func wmiServiceMethod(services *ole.IDispatch, name, method string, accepted map[int64]bool) error {
	result, err := wmiExecMethod(services, wmiServicePath(name), method, nil)
	if err != nil {
		return err
	}
	defer result.Release()
	returnValue, err := oleutil.GetProperty(result, "ReturnValue")
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	if !accepted[returnValue.Val] {
		return errs.New(errs.Execution, "Win32_Service.%s returned %d", method, returnValue.Val)
	}
	return nil
}

func wmiServicePath(name string) string {
	return fmt.Sprintf("Win32_Service.Name='%s'", wqlEscape(name))
}

func wmiExecMethod(services *ole.IDispatch, objectPath, method string, inputs map[string]any) (*ole.IDispatch, error) {
	objectRaw, err := oleutil.CallMethod(services, "Get", objectPath)
	if err != nil {
		return nil, errs.Wrap(errs.Execution, fmt.Errorf("get WMI object %s: %w", objectPath, err))
	}
	object, err := variantDispatch(objectRaw, "WMI object "+objectPath)
	if err != nil {
		return nil, err
	}
	defer object.Release()

	var input *ole.IDispatch
	if len(inputs) > 0 {
		methodsRaw, err := oleutil.GetProperty(object, "Methods_")
		if err != nil {
			return nil, errs.Wrap(errs.Execution, err)
		}
		methods, err := variantDispatch(methodsRaw, "WMI method set")
		if err != nil {
			return nil, err
		}
		defer methods.Release()
		methodRaw, err := oleutil.CallMethod(methods, "Item", method)
		if err != nil {
			return nil, errs.Wrap(errs.Execution, err)
		}
		methodObject, err := variantDispatch(methodRaw, "WMI method "+method)
		if err != nil {
			return nil, err
		}
		defer methodObject.Release()
		definitionRaw, err := oleutil.GetProperty(methodObject, "InParameters")
		if err != nil {
			return nil, errs.Wrap(errs.Execution, err)
		}
		definition, err := variantDispatch(definitionRaw, "WMI input definition for "+method)
		if err != nil {
			return nil, err
		}
		defer definition.Release()
		inputRaw, err := oleutil.CallMethod(definition, "SpawnInstance_")
		if err != nil {
			return nil, errs.Wrap(errs.Execution, err)
		}
		input, err = variantDispatch(inputRaw, "WMI input instance for "+method)
		if err != nil {
			return nil, err
		}
		defer input.Release()
		for name, value := range inputs {
			if _, err := oleutil.PutProperty(input, name, value); err != nil {
				return nil, errs.Wrap(errs.Execution, fmt.Errorf("set WMI input %s: %w", name, err))
			}
		}
	}

	resultRaw, err := oleutil.CallMethod(services, "ExecMethod", objectPath, method, input)
	if err != nil {
		return nil, errs.Wrap(errs.Execution, fmt.Errorf("execute WMI method %s: %w", method, err))
	}
	return variantDispatch(resultRaw, "WMI output for "+method)
}

func variantDispatch(value *ole.VARIANT, description string) (*ole.IDispatch, error) {
	if value == nil {
		return nil, errs.New(errs.Execution, "%s returned no value", description)
	}
	dispatch := value.ToIDispatch()
	if dispatch == nil {
		return nil, errs.New(errs.Execution, "%s returned variant type %d, expected dispatch", description, value.VT)
	}
	return dispatch, nil
}

func wmiProviderRegister(services *ole.IDispatch, name, clsid string) error {
	classRaw, err := oleutil.CallMethod(services, "Get", "__Win32Provider")
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	class := classRaw.ToIDispatch()
	defer class.Release()
	instanceRaw, err := oleutil.CallMethod(class, "SpawnInstance_")
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	instance := instanceRaw.ToIDispatch()
	defer instance.Release()
	if _, err := oleutil.PutProperty(instance, "Name", name); err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	if _, err := oleutil.PutProperty(instance, "Clsid", clsid); err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	if _, err := oleutil.PutProperty(instance, "HostingModel", "LocalSystemHost:"+name); err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	put, err := oleutil.CallMethod(instance, "Put_", 0)
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	put.Clear()
	return nil
}

func wmiProviderDelete(services *ole.IDispatch, name string) error {
	del, err := oleutil.CallMethod(services, "Delete", fmt.Sprintf(`__Win32Provider.Name='%s'`, wqlEscape(name)))
	if err != nil {
		return errs.Wrap(errs.Cleanup, err)
	}
	del.Clear()
	return nil
}

func wmiProviderExists(services *ole.IDispatch, name string) (bool, error) {
	raw, err := oleutil.CallMethod(services, "Get", fmt.Sprintf(`__Win32Provider.Name='%s'`, wqlEscape(name)))
	if err != nil {
		return false, nil
	}
	raw.ToIDispatch().Release()
	return true, nil
}

const hkeyLocalMachine = uint32(0x80000002)

func providerCOMSubkey(clsid string) string {
	return `SOFTWARE\Classes\CLSID\` + clsid
}

func wmiMethodReturn(services *ole.IDispatch, object, method string, inputs map[string]any) (*ole.IDispatch, error) {
	result, err := wmiExecMethod(services, object, method, inputs)
	if err != nil {
		return nil, err
	}
	returnValue, err := oleutil.GetProperty(result, "ReturnValue")
	if err != nil {
		result.Release()
		return nil, errs.Wrap(errs.Execution, err)
	}
	if returnValue.Val != 0 {
		result.Release()
		return nil, errs.New(errs.Execution, "%s.%s returned %d", object, method, returnValue.Val)
	}
	return result, nil
}

func wmiProviderCOMRegister(services *ole.IDispatch, clsid, dllPath string) error {
	leaf := providerCOMSubkey(clsid) + `\InprocServer32`
	result, err := wmiMethodReturn(services, "StdRegProv", "CreateKey", map[string]any{
		"hDefKey": hkeyLocalMachine, "sSubKeyName": leaf,
	})
	if err != nil {
		return err
	}
	result.Release()
	for name, value := range map[string]string{"": dllPath, "ThreadingModel": "Both"} {
		result, err = wmiMethodReturn(services, "StdRegProv", "SetStringValue", map[string]any{
			"hDefKey": hkeyLocalMachine, "sSubKeyName": leaf, "sValueName": name, "sValue": value,
		})
		if err != nil {
			return err
		}
		result.Release()
	}
	return nil
}

func wmiProviderCOMDelete(services *ole.IDispatch, clsid string) error {
	root := providerCOMSubkey(clsid)
	for _, key := range []string{root + `\InprocServer32`, root} {
		result, err := wmiMethodReturn(services, "StdRegProv", "DeleteKey", map[string]any{
			"hDefKey": hkeyLocalMachine, "sSubKeyName": key,
		})
		if err != nil {
			return err
		}
		result.Release()
	}
	return nil
}

func wmiProviderCOMExists(services *ole.IDispatch, clsid string) (bool, error) {
	result, err := wmiExecMethod(services, "StdRegProv", "GetStringValue", map[string]any{
		"hDefKey": hkeyLocalMachine, "sSubKeyName": providerCOMSubkey(clsid) + `\InprocServer32`, "sValueName": "",
	})
	if err != nil {
		return false, err
	}
	defer result.Release()
	returnValue, err := oleutil.GetProperty(result, "ReturnValue")
	if err != nil {
		return false, errs.Wrap(errs.Execution, err)
	}
	if returnValue.Val == 2 {
		return false, nil
	}
	if returnValue.Val != 0 {
		return false, errs.New(errs.Execution, "StdRegProv.GetStringValue returned %d", returnValue.Val)
	}
	return true, nil
}

func wmiProviderLoad(services *ole.IDispatch, namespace, name string) error {
	classRaw, err := oleutil.CallMethod(services, "Get", "MSFT_Providers")
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	class := classRaw.ToIDispatch()
	defer class.Release()
	methodsRaw, err := oleutil.GetProperty(class, "Methods_")
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	methods := methodsRaw.ToIDispatch()
	defer methods.Release()
	methodRaw, err := oleutil.CallMethod(methods, "Item", "Load")
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	method := methodRaw.ToIDispatch()
	defer method.Release()
	inputClassRaw, err := oleutil.GetProperty(method, "InParameters")
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	inputClass := inputClassRaw.ToIDispatch()
	defer inputClass.Release()
	inputRaw, err := oleutil.CallMethod(inputClass, "SpawnInstance_")
	if err != nil {
		return errs.Wrap(errs.Execution, err)
	}
	input := inputRaw.ToIDispatch()
	defer input.Release()
	for property, value := range map[string]any{
		"Namespace": namespace, "User": nil, "Locale": nil, "provider": name, "TransactionIdentifier": nil,
	} {
		if _, err := oleutil.PutProperty(input, property, value); err != nil {
			return errs.Wrap(errs.Execution, err)
		}
	}
	output, err := oleutil.CallMethod(services, "ExecMethod", "MSFT_Providers", "Load", input)
	if err != nil {
		return errs.Wrap(errs.Execution, fmt.Errorf("execute WMI method Load: %w", err))
	}
	// MSFT_Providers.Load may return a null VT_DISPATCH on success.
	if dispatch := output.ToIDispatch(); dispatch != nil {
		defer dispatch.Release()
		if returnValue, err := oleutil.GetProperty(dispatch, "ReturnValue"); err == nil && returnValue.Val != 0 {
			return errs.New(errs.Execution, "MSFT_Providers.Load returned %d", returnValue.Val)
		}
	}
	return nil
}

func wmiProviderUnload(services *ole.IDispatch, namespace, name string) error {
	// Provider and Namespace are awkward WQL identifiers on current Windows
	// builds. Enumerate the small troubleshooting class and match in-process
	// rather than relying on a filter the provider rejects as invalid syntax.
	raw, err := oleutil.CallMethod(services, "ExecQuery", "SELECT * FROM MSFT_Providers")
	if err != nil {
		return errs.Wrap(errs.Cleanup, err)
	}
	instances := raw.ToIDispatch()
	defer instances.Release()
	found := false
	err = oleutil.ForEach(instances, func(value *ole.VARIANT) error {
		if found {
			return nil
		}
		item := value.ToIDispatch()
		defer item.Release()
		providerValue, err := oleutil.GetProperty(item, "provider")
		if err != nil || !strings.EqualFold(providerValue.ToString(), name) {
			return nil
		}
		namespaceValue, err := oleutil.GetProperty(item, "Namespace")
		if err != nil || !strings.EqualFold(namespaceValue.ToString(), namespace) {
			return nil
		}
		pathRaw, err := oleutil.GetProperty(item, "Path_")
		if err != nil {
			return err
		}
		path := pathRaw.ToIDispatch()
		if path == nil {
			return fmt.Errorf("MSFT_Providers instance has no path")
		}
		defer path.Release()
		pathValue, err := oleutil.GetProperty(path, "Path")
		if err != nil {
			return err
		}
		output, err := oleutil.CallMethod(services, "ExecMethod", pathValue.ToString(), "UnLoad", nil)
		if err != nil {
			return err
		}
		// Like Load, UnLoad can return a null VT_DISPATCH on success.
		if dispatch := output.ToIDispatch(); dispatch != nil {
			dispatch.Release()
		}
		found = true
		return nil
	})
	if err != nil {
		return errs.Wrap(errs.Cleanup, err)
	}
	return nil
}
