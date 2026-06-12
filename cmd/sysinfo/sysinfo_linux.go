//go:build linux

package main

import "github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"

func gatherSysinfo() (string, string) {
	sections := []struct {
		name string
		cmd  string
	}{
		{"=== OS ===", "cat /etc/os-release 2>/dev/null; uname -a"},
		{"=== INTERFACES ===", "ip addr 2>/dev/null || ifconfig -a"},
		{"=== DNS ===", "cat /etc/resolv.conf"},
		{"=== PATCHES ===", "rpm -qa 2>/dev/null | tail -50 || dpkg -l 2>/dev/null | tail -50"},
		{"=== DISK ===", "df -h"},
		{"=== MEMORY ===", "free -h"},
	}
	var out, errAll string
	for _, s := range sections {
		o, e := shared.RunShell(s.cmd)
		out += s.name + "\n" + o + "\n"
		errAll += e
	}
	return out, errAll
}
