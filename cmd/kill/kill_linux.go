//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
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
	childrenDir := filepath.Join("/proc", strconv.Itoa(pid), "task", strconv.Itoa(pid), "children")
	data, err := os.ReadFile(childrenDir)
	if err != nil {
		return
	}
	for _, c := range strings.Fields(string(data)) {
		if cpid, err := strconv.Atoi(c); err == nil {
			killTree(cpid)
			shared.Run("kill", "-9", c)
		}
	}
}
