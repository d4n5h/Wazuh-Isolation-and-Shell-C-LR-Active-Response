//go:build windows

package main

import (
	"fmt"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

func userAction(action, target string) (string, string) {
	switch action {
	case "disable":
		return shared.RunShell(fmt.Sprintf(`net user "%s" /active:no`, target))
	case "enable":
		return shared.RunShell(fmt.Sprintf(`net user "%s" /active:yes`, target))
	case "logoff":
		if target == "" {
			return "", "extra_args[0] must be session ID for logoff"
		}
		return shared.RunShell(fmt.Sprintf("logoff %s", target))
	default:
		return "", "No action provided. Use: disable, enable, logoff"
	}
}
