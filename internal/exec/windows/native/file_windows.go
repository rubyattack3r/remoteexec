//go:build windows

package native

import (
	"context"
	"errors"

	"github.com/rubyattack3r/remoteexec/internal/exec/errs"
	adapter "github.com/rubyattack3r/remoteexec/internal/exec/windows/technique"
	"golang.org/x/sys/windows"
)

// uncPath maps a local drive path onto the target administrative share,
// e.g. C:\Windows\Temp\x.dll -> \\target\C$\Windows\Temp\x.dll.
func uncPath(target, path string) string {
	if len(path) >= 2 && path[1] == ':' {
		return `\\` + target + `\` + string(path[0]) + `$` + path[2:]
	}
	return path
}

func writeFile(ctx context.Context, target, path string, content []byte, ident identity) (string, error) {
	var writeErr error
	ident.run(func() error {
		handle, err := windows.CreateFile(windows.StringToUTF16Ptr(uncPath(target, path)), windows.GENERIC_WRITE, 0, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			if isErrno(err, windows.ERROR_FILE_EXISTS) || isErrno(err, windows.ERROR_ALREADY_EXISTS) {
				writeErr = errs.New(errs.Conflict, "staging path %s already exists", path)
				return nil
			}
			writeErr = errs.Wrap(errs.Execution, err)
			return nil
		}
		defer windows.CloseHandle(handle)
		var written uint32
		if err := windows.WriteFile(handle, content, &written, nil); err != nil {
			writeErr = errs.Wrap(errs.Execution, err)
			return nil
		}
		if int(written) != len(content) {
			writeErr = errs.New(errs.Execution, "short write to %s", path)
		}
		return nil
	})
	if writeErr != nil {
		return "", writeErr
	}
	readBack, err := readFile(ctx, target, path, ident)
	if err != nil {
		return "", err
	}
	return adapter.Digest(readBack), nil
}

func readFile(ctx context.Context, target, path string, ident identity) ([]byte, error) {
	var data []byte
	var readErr error
	ident.run(func() error {
		handle, err := windows.CreateFile(windows.StringToUTF16Ptr(uncPath(target, path)), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if err != nil {
			readErr = errs.Wrap(errs.Execution, err)
			return nil
		}
		defer windows.CloseHandle(handle)
		var all []byte
		buffer := make([]byte, 64*1024)
		for {
			var read uint32
			if err := windows.ReadFile(handle, buffer, &read, nil); err != nil {
				readErr = errs.Wrap(errs.Execution, err)
				return nil
			}
			if read == 0 {
				break
			}
			all = append(all, buffer[:read]...)
		}
		data = all
		return nil
	})
	return data, readErr
}

func removeFile(ctx context.Context, target, path string, ident identity) error {
	return ident.run(func() error {
		if err := windows.DeleteFile(windows.StringToUTF16Ptr(uncPath(target, path))); err != nil {
			return errs.Wrap(errs.Cleanup, err)
		}
		return nil
	})
}

func fileExists(ctx context.Context, target, path string, ident identity) (bool, error) {
	var exists bool
	ident.run(func() error {
		attrs, err := windows.GetFileAttributes(windows.StringToUTF16Ptr(uncPath(target, path)))
		exists = err == nil && attrs != windows.INVALID_FILE_ATTRIBUTES
		return nil
	})
	return exists, nil
}

func globFiles(ctx context.Context, target, pattern string, ident identity) ([]string, error) {
	var names []string
	var globErr error
	ident.run(func() error {
		data := &windows.Win32finddata{}
		handle, err := windows.FindFirstFile(windows.StringToUTF16Ptr(uncPath(target, pattern)), data)
		if err != nil {
			if isErrno(err, windows.ERROR_FILE_NOT_FOUND) || isErrno(err, windows.ERROR_PATH_NOT_FOUND) || isErrno(err, windows.ERROR_NO_MORE_FILES) {
				return nil
			}
			globErr = errs.Wrap(errs.Reachability, err)
			return nil
		}
		defer windows.CloseHandle(handle)
		names = append(names, windows.UTF16ToString(data.FileName[:]))
		for {
			data = &windows.Win32finddata{}
			if err := windows.FindNextFile(handle, data); err != nil {
				if !isErrno(err, windows.ERROR_NO_MORE_FILES) {
					globErr = errs.Wrap(errs.Reachability, err)
				}
				break
			}
			names = append(names, windows.UTF16ToString(data.FileName[:]))
		}
		return nil
	})
	return names, globErr
}

func isErrno(err error, code windows.Errno) bool {
	var errno windows.Errno
	return errors.As(err, &errno) && errno == code
}
