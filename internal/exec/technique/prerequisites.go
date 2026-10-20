package technique

import (
	"fmt"
	"strings"
)

type Requirement string

const (
	RequireLocalAdmin      Requirement = "local_admin"
	RequireWMI             Requirement = "wmi"
	RequireRemoteRegistry  Requirement = "remote_registry"
	RequireWinRM           Requirement = "winrm"
	RequireDCOM            Requirement = "dcom"
	RequireTaskScheduler   Requirement = "task_scheduler"
	RequireActiveShell     Requirement = "active_shell"
	RequireSCM             Requirement = "scm"
	RequireExistingService Requirement = "existing_service"
	RequireServiceSnapshot Requirement = "service_snapshot"
	RequireSSH             Requirement = "ssh"
)

// Capabilities are collected read-only by an execution backend before staging.
type Capabilities struct {
	LocalAdmin      bool
	WMI             bool
	RemoteRegistry  bool
	WinRM           bool
	DCOM            bool
	TaskScheduler   bool
	ActiveShell     bool
	SCM             bool
	ExistingService bool
	ServiceSnapshot bool
	SSH             bool
}

func (d Descriptor) ValidatePrerequisites(c Capabilities) error {
	missing := make([]string, 0)
	for _, requirement := range d.Requirements {
		ok := false
		switch requirement {
		case RequireLocalAdmin:
			ok = c.LocalAdmin
		case RequireWMI:
			ok = c.WMI
		case RequireRemoteRegistry:
			ok = c.RemoteRegistry
		case RequireWinRM:
			ok = c.WinRM
		case RequireDCOM:
			ok = c.DCOM
		case RequireTaskScheduler:
			ok = c.TaskScheduler
		case RequireActiveShell:
			ok = c.ActiveShell
		case RequireSCM:
			ok = c.SCM
		case RequireExistingService:
			ok = c.ExistingService
		case RequireServiceSnapshot:
			ok = c.ServiceSnapshot
		case RequireSSH:
			ok = c.SSH
		}
		if !ok {
			missing = append(missing, string(requirement))
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("%s prerequisites not met: %s", d.Name, strings.Join(missing, ", "))
	}
	return nil
}
