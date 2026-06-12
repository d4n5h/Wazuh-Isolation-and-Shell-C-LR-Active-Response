//go:build windows

package main

import "github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"

func collectProcesses() (string, string) {
	return shared.RunShell("tasklist /V /FO CSV")
}

func collectConnections() (string, string) {
	return shared.RunShell("netstat -ano")
}

func collectUsers() (string, string) {
	out1, err1 := shared.RunShell("query user")
	out2, err2 := shared.RunShell("net session")
	return out1 + "\n" + out2, err1 + err2
}

func collectServices() (string, string) {
	return shared.RunShell("sc query state= all")
}

func collectAutoruns() (string, string) {
	out1, err1 := shared.RunShell("schtasks /query /fo LIST /v")
	out2, err2 := shared.RunShell(`reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run /s`)
	out3, err3 := shared.RunShell(`reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /s`)
	return out1 + "\n" + out2 + "\n" + out3, err1 + err2 + err3
}
