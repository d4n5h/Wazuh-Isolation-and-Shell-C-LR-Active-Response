//go:build darwin

package main

import (
	"fmt"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

func collectEvtLog(channel, count string) (string, string) {
	return "", "evtlog action not supported on macOS"
}

func collectJournal(unit, count string) (string, string) {
	return "", "journal action not supported on macOS"
}

func collectFile(path, count string) (string, string) {
	return shared.RunShell(fmt.Sprintf("tail -n %s %q", count, path))
}
