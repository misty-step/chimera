//go:build !unix

package lane

import "os/exec"

func setProcessGroup(cmd *exec.Cmd) {}
