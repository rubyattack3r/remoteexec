// Package config contains runtime configuration shared by the command tree.
package config

import "time"

// RootFlags contains options inherited by every command.
type RootFlags struct {
	Output  string
	Timeout time.Duration
	Sleep   time.Duration
	Jitter  float64
	Verbose bool
	Auth    string
}
