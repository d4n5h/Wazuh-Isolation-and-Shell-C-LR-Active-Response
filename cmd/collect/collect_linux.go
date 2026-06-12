//go:build linux

package main

import "github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"

func collectProcesses() (string, string) {
	return shared.RunShell("ps auxww")
}

func collectConnections() (string, string) {
	out, err := shared.RunShell("ss -tunap 2>/dev/null")
	if err != "" {
		return shared.RunShell("netstat -tunap 2>/dev/null || cat /proc/net/tcp /proc/net/udp")
	}
	return out, err
}

func collectUsers() (string, string) {
	out1, err1 := shared.RunShell("who")
	out2, err2 := shared.RunShell("w")
	return out1 + "\n" + out2, err1 + err2
}

func collectServices() (string, string) {
	return shared.RunShell("systemctl list-units --type=service --all 2>/dev/null || service --status-all 2>/dev/null")
}

func collectAutoruns() (string, string) {
	out1, err1 := shared.RunShell("crontab -l 2>/dev/null; ls -la /etc/cron.* 2>/dev/null")
	out2, err2 := shared.RunShell("systemctl list-timers --all 2>/dev/null")
	out3, err3 := shared.RunShell("ls -la /etc/init.d/ 2>/dev/null")
	return out1 + "\n" + out2 + "\n" + out3, err1 + err2 + err3
}
