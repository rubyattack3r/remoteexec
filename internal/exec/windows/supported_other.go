//go:build !windows

package windows

// Supported reports whether the Windows-native backend is available in this
// build. Non-Windows builds can still validate Windows plans with --dry-run.
func Supported() bool { return false }
