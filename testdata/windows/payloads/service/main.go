package main

import (
	"os"
	"time"

	"golang.org/x/sys/windows/svc"
)

const markerPath = `C:\Windows\Temp\remoteexec-service.marker`

type handler struct{}

func (handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	if err := os.WriteFile(markerPath, []byte("remoteexec service fixture\r\n"), 0o600); err != nil {
		return false, 1
	}
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}

	timer := time.NewTimer(10 * time.Second)
	defer timer.Stop()
	for {
		select {
		case request := <-requests:
			switch request.Cmd {
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				return false, 0
			case svc.Interrogate:
				status <- request.CurrentStatus
			}
		case <-timer.C:
			status <- svc.Status{State: svc.StopPending}
			return false, 0
		}
	}
}

func main() {
	if err := svc.Run("", handler{}); err != nil {
		os.Exit(1)
	}
}
