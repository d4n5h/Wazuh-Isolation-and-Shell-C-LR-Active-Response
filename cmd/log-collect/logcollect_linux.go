//go:build linux

package main

import (
	"fmt"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

func collectEvtLog(channel, count string) (string, string) {
	return "", "evtlog action not supported on Linux"
}

func collectJournal(unit, count string) (string, string) {
	return shared.RunShell(fmt.Sprintf("journalctl -u %s -n %s --no-pager", unit, count))
}

func collectFile(path, count string) (string, string) {
	return shared.RunShell(fmt.Sprintf("tail -n %s %q", count, path))
}
