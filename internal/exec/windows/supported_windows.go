//go:build windows

package windows

// Supported reports whether this build can perform live, read-only preflight
// checks against targets from the host remoteexec runs on.
func Supported() bool { return true }
