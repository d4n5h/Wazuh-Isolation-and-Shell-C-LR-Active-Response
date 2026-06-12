//go:build darwin

package main

import (
	"fmt"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

func userAction(action, target string) (string, string) {
	switch action {
	case "disable":
		return shared.Run("pwpolicy", "-u", target, "-setpolicy", "newPasswordRequired=1")
	case "enable":
		return shared.Run("pwpolicy", "-u", target, "-setpolicy", "newPasswordRequired=0")
	case "logoff":
		if target == "" {
			return "", "extra_args[0] must be username for logoff"
		}
		return shared.RunShell(fmt.Sprintf("pkill -u %q", target))
	default:
		return "", "No action provided. Use: disable, enable, logoff"
	}
}
