//go:build windows

package main

import "github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"

func gatherSysinfo() (string, string) {
	sections := []struct {
		name string
		cmd  string
	}{
		{"=== OS ===", "systeminfo"},
		{"=== INTERFACES ===", "ipconfig /all"},
		{"=== PATCHES ===", "wmic qfe list brief"},
		{"=== DISK ===", "wmic logicaldisk get size,freespace,caption"},
	}
	var out, errAll string
	for _, s := range sections {
		o, e := shared.RunShell(s.cmd)
		out += s.name + "\n" + o + "\n"
		errAll += e
	}
	return out, errAll
}
