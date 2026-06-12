//go:build windows

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
		{"=== RUN KEYS (HKLM) ===", `reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run /s`},
		{"=== RUN KEYS (HKCU) ===", `reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run /s`},
		{"=== SCHEDULED TASKS ===", "schtasks /query /fo LIST /v"},
		{"=== SERVICES ===", "sc query type= service state= all"},
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
	case "scheduled":
		return shared.RunShell(fmt.Sprintf(`schtasks /delete /tn "%s" /f`, id))
	case "service":
		return shared.RunShell(fmt.Sprintf(`sc delete "%s"`, id))
	case "runkey":
		return shared.RunShell(fmt.Sprintf(`reg delete "%s" /f`, id))
	default:
		return "", fmt.Sprintf("unknown type: %s (use: scheduled, service, runkey)", entryType)
	}
}
