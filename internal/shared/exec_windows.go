//go:build windows

package shared

import (
	"os/exec"
)

func Run(name string, args ...string) (string, string) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return string(out), string(exitErr.Stderr)
		}
		return string(out), err.Error()
	}
	return string(out), ""
}

func RunShell(command string) (string, string) {
	return Run("cmd", "/c", command)
}
