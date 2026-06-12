//go:build linux

package main

import (
	"fmt"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

func scanPersistence() (string, string) {
	sections := []struct {
		name string
		cmd  string
	}{
		{"=== CRON ===", "crontab -l 2>/dev/null; ls -la /etc/cron.* 2>/dev/null"},
		{"=== SYSTEMD TIMERS ===", "systemctl list-timers --all 2>/dev/null"},
		{"=== SYSTEMD SERVICES ===", "systemctl list-unit-files --type=service 2>/dev/null"},
		{"=== INIT.D ===", "ls -la /etc/init.d/ 2>/dev/null"},
		{"=== XDG AUTOSTART ===", "ls -la /etc/xdg/autostart ~/.config/autostart 2>/dev/null"},
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
	case "cron":
		return shared.RunShell(fmt.Sprintf("crontab -l | grep -v %q | crontab -", id))
	case "service":
		return shared.Run("systemctl", "disable", "--now", id)
	case "timer":
		return shared.Run("systemctl", "disable", "--now", id)
	default:
		return "", fmt.Sprintf("unknown type: %s (use: cron, service, timer)", entryType)
	}
}
