//go:build unix

package lane

import (
	"os/exec"
	"syscall"
)

// setProcessGroup puts the command in its own process group and kills the
// whole group on cancellation, so a harness cannot leave children behind.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
}

// killProcessGroup kills whatever is left of the command's process group
// after the command itself has been waited for.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
