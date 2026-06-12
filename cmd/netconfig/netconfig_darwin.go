//go:build darwin

package main

import (
	"fmt"

	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
)

func flushDNS() (string, string) {
	return shared.RunShell("dscacheutil -flushcache; killall -HUP mDNSResponder 2>/dev/null")
}

func flushARP() (string, string) {
	return shared.RunShell("arp -d -a")
}

func resetAdapter(name string) (string, string) {
	out1, e1 := shared.RunShell(fmt.Sprintf("ifconfig %s down", name))
	out2, e2 := shared.RunShell(fmt.Sprintf("ifconfig %s up", name))
	return out1 + out2, e1 + e2
}
