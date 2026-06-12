//go:build darwin

package main

import "github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"

func gatherSysinfo() (string, string) {
	sections := []struct {
		name string
		cmd  string
	}{
		{"=== OS ===", "sw_vers; uname -a"},
		{"=== INTERFACES ===", "ifconfig -a"},
		{"=== DNS ===", "scutil --dns 2>/dev/null | head -50"},
		{"=== PATCHES ===", "softwareupdate --history 2>/dev/null | tail -30"},
		{"=== DISK ===", "df -h"},
		{"=== MEMORY ===", "vm_stat"},
	}
	var out, errAll string
	for _, s := range sections {
		o, e := shared.RunShell(s.cmd)
		out += s.name + "\n" + o + "\n"
		errAll += e
	}
	return out, errAll
}
