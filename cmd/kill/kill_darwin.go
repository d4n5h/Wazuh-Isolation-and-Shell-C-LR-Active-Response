//go:build darwin

package main

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

func killProcess(target string, tree bool) (string, string) {
	pid, err := strconv.Atoi(target)
	if err != nil {
		return shared.RunShell(fmt.Sprintf("pkill -9 -f %q", target))
	}
	if tree {
		killTree(pid)
	}
	return shared.Run("kill", "-9", strconv.Itoa(pid))
}

func killTree(pid int) {
	out, _ := shared.RunShell(fmt.Sprintf("pgrep -P %d", pid))
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if cpid, err := strconv.Atoi(strings.TrimSpace(line)); err == nil {
			killTree(cpid)
			shared.Run("kill", "-9", line)
		}
	}
}
