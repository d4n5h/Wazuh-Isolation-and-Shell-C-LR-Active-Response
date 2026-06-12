//go:build windows

package main

import (
	"fmt"

	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
)

func collectEvtLog(channel, count string) (string, string) {
	return shared.RunShell(fmt.Sprintf(`wevtutil qe "%s" /c:%s /rd:true /f:text`, channel, count))
}

func collectJournal(unit, count string) (string, string) {
	return "", "journal action not supported on Windows"
}

func collectFile(path, count string) (string, string) {
	return shared.RunShell(fmt.Sprintf(`powershell -NoProfile -Command "Get-Content -Tail %s -Path '%s'"`, count, path))
}
