//go:build windows

package main

import (
	"fmt"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

func flushDNS() (string, string) {
	return shared.RunShell("ipconfig /flushdns")
}

func flushARP() (string, string) {
	return shared.RunShell("arp -d *")
}

func resetAdapter(name string) (string, string) {
	out1, e1 := shared.RunShell(fmt.Sprintf(`netsh interface set interface "%s" disable`, name))
	out2, e2 := shared.RunShell(fmt.Sprintf(`netsh interface set interface "%s" enable`, name))
	return out1 + out2, e1 + e2
}
