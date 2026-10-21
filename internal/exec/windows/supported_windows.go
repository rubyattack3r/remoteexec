//go:build windows

package windows

// Supported reports whether the Windows-native backend is available in this
// build.
func Supported() bool { return true }
