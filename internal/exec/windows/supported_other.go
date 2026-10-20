//go:build !windows

package windows

// Supported reports whether this build can perform live, read-only preflight
// checks against targets. Non-Windows builds validate plans locally only.
func Supported() bool { return false }
