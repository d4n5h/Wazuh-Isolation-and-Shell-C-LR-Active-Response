//go:build darwin

package main

import (
	"fmt"
	"os"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

func scanPersistence() (string, string) {
	sections := []struct {
		name string
		cmd  string
	}{
		{"=== LAUNCH AGENTS ===", "ls -la ~/Library/LaunchAgents /Library/LaunchAgents 2>/dev/null"},
		{"=== LAUNCH DAEMONS ===", "ls -la /Library/LaunchDaemons 2>/dev/null"},
		{"=== LAUNCHCTL ===", "launchctl list"},
		{"=== CRON ===", "crontab -l 2>/dev/null"},
	}
	var out, errAll string
	for _, s := range sections {
		o, e := shared.RunShell(s.cmd)
		out += s.name + "\n" + o + "\n"
		errAll += e
	}
	return out, errAll
}

func removePersistence(entryType, id string) (string, string) {
	switch entryType {
	case "launchagent", "launchdaemon":
		if err := os.Remove(id); err != nil {
			return "", err.Error()
		}
		return fmt.Sprintf("removed %s", id), ""
	case "cron":
		return shared.RunShell(fmt.Sprintf("crontab -l | grep -v %q | crontab -", id))
	default:
		return "", fmt.Sprintf("unknown type: %s (use: launchagent, launchdaemon, cron)", entryType)
	}
}
