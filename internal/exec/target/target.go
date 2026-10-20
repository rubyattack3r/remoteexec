// Package target defines platform-neutral target identity and transport metadata.
package target

type Platform string

const (
	Windows Platform = "windows"
	Linux   Platform = "linux"
	Darwin  Platform = "darwin"
)

func (p Platform) Valid() bool {
	switch p {
	case Windows, Linux, Darwin:
		return true
	default:
		return false
	}
}

type Transport string

const (
	Native Transport = "native"
	SSH    Transport = "ssh"
)

type Metadata struct {
	Platform  Platform  `json:"platform" yaml:"platform"`
	Transport Transport `json:"transport" yaml:"transport"`
}

func (m Metadata) Valid() bool {
	return m.Platform != "" && m.Transport != ""
}
