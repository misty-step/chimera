//go:build !unix

package inlet

import "os/exec"

func setProcessGroup(*exec.Cmd)  {}
func killProcessGroup(*exec.Cmd) {}
