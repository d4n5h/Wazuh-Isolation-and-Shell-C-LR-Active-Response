//go:build windows

package main

import (
	"fmt"
	"strings"

	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
)

const rulePrefix = "C-LR-"

func blockIP(ip string) (string, string) {
	name := rulePrefix + "block-ip-" + strings.ReplaceAll(ip, "/", "-")
	out1, err1 := shared.RunShell(fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=in action=block remoteip=%s enable=yes`, name, ip))
	out2, err2 := shared.RunShell(fmt.Sprintf(`netsh advfirewall firewall add rule name="%s-out" dir=out action=block remoteip=%s enable=yes`, name, ip))
	return out1 + out2, err1 + err2
}

func blockPort(spec string) (string, string) {
	port := spec
	proto := "tcp"
	if parts := strings.Split(spec, ":"); len(parts) == 2 {
		port, proto = parts[0], parts[1]
	}
	name := rulePrefix + "block-port-" + port + "-" + proto
	return shared.RunShell(fmt.Sprintf(`netsh advfirewall firewall add rule name="%s" dir=in action=block protocol=%s localport=%s enable=yes`, name, proto, port))
}

func unblockRule(label string) (string, string) {
	name := label
	if !strings.HasPrefix(name, rulePrefix) {
		name = rulePrefix + label
	}
	out1, err1 := shared.RunShell(fmt.Sprintf(`netsh advfirewall firewall delete rule name="%s"`, name))
	out2, err2 := shared.RunShell(fmt.Sprintf(`netsh advfirewall firewall delete rule name="%s-out"`, name))
	return out1 + out2, err1 + err2
}

func listRules() (string, string) {
	return shared.RunShell(fmt.Sprintf(`netsh advfirewall firewall show rule name=all | findstr /i "%s"`, rulePrefix))
}
