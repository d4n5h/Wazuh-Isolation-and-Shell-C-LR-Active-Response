//go:build linux

package main

import (
	"fmt"

	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
)

func userAction(action, target string) (string, string) {
	switch action {
	case "disable":
		return shared.Run("usermod", "-L", target)
	case "enable":
		return shared.Run("usermod", "-U", target)
	case "logoff":
		if target == "" {
			return "", "extra_args[0] must be username for logoff"
		}
		return shared.RunShell(fmt.Sprintf("pkill -u %q", target))
	default:
		return "", "No action provided. Use: disable, enable, logoff"
	}
}
