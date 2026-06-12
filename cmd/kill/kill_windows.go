//go:build windows

package main

import (
	"strconv"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

func killProcess(target string, tree bool) (string, string) {
	args := []string{"/F"}
	if tree {
		args = append(args, "/T")
	}
	if _, err := strconv.Atoi(target); err == nil {
		args = append(args, "/PID", target)
	} else {
		args = append(args, "/IM", target)
	}
	return shared.Run("taskkill", args...)
}
