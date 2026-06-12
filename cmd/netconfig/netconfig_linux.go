//go:build linux

package main

import (
	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
)

func flushDNS() (string, string) {
	return shared.RunShell("resolvectl flush-caches 2>/dev/null || systemd-resolve --flush-caches 2>/dev/null")
}

func flushARP() (string, string) {
	return shared.RunShell("ip neigh flush all")
}

func resetAdapter(name string) (string, string) {
	out1, e1 := shared.Run("ip", "link", "set", name, "down")
	out2, e2 := shared.Run("ip", "link", "set", name, "up")
	return out1 + out2, e1 + e2
}
