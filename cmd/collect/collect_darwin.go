//go:build darwin

package main

import "github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"

func collectProcesses() (string, string) {
	return shared.RunShell("ps auxww")
}

func collectConnections() (string, string) {
	out, err := shared.RunShell("netstat -anv")
	if err != "" {
		return shared.RunShell("lsof -i -n -P")
	}
	return out, err
}

func collectUsers() (string, string) {
	out1, err1 := shared.RunShell("who")
	out2, err2 := shared.RunShell("w")
	return out1 + "\n" + out2, err1 + err2
}

func collectServices() (string, string) {
	return shared.RunShell("launchctl list")
}

func collectAutoruns() (string, string) {
	out1, err1 := shared.RunShell("ls -la ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons 2>/dev/null")
	out2, err2 := shared.RunShell("crontab -l 2>/dev/null")
	return out1 + "\n" + out2, err1 + err2
}
