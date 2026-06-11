//go:build windows

package main

import (
	"os/exec"
)

func cmdRun(command string) (string, string) {
	cmd := exec.Command("cmd", "/c", command)
	out, err := cmd.Output()
	stderr := ""
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
		} else {
			stderr = err.Error()
		}
	}
	return string(out), stderr
}
