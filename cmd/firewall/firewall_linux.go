//go:build linux

package main

import (
	"fmt"
	"strings"

	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
)

const chain = "CLR_FW"

func detectBackend() string {
	if _, err := shared.Run("which", "nft"); err == "" {
		return "nft"
	}
	return "iptables"
}

func blockIP(ip string) (string, string) {
	if detectBackend() == "nft" {
		shared.RunShell(fmt.Sprintf("nft list table inet %s 2>/dev/null || nft add table inet %s", chain, chain))
		shared.RunShell(fmt.Sprintf("nft list chain inet %s input 2>/dev/null || nft add chain inet %s input { type filter hook input priority 0\\; policy accept\\; }", chain, chain))
		shared.RunShell(fmt.Sprintf("nft list chain inet %s output 2>/dev/null || nft add chain inet %s output { type filter hook output priority 0\\; policy accept\\; }", chain, chain))
		out1, e1 := shared.RunShell(fmt.Sprintf("nft add rule inet %s input ip saddr %s drop comment \"clr-block-ip\"", chain, ip))
		out2, e2 := shared.RunShell(fmt.Sprintf("nft add rule inet %s output ip daddr %s drop comment \"clr-block-ip\"", chain, ip))
		return out1 + out2, e1 + e2
	}
	out1, e1 := shared.Run("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	out2, e2 := shared.Run("iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP")
	return out1 + out2, e1 + e2
}

func blockPort(spec string) (string, string) {
	port := spec
	proto := "tcp"
	if parts := strings.Split(spec, ":"); len(parts) == 2 {
		port, proto = parts[0], parts[1]
	}
	if detectBackend() == "nft" {
		return shared.RunShell(fmt.Sprintf("nft add rule inet %s input %s dport %s drop comment \"clr-block-port\"", chain, proto, port))
	}
	return shared.Run("iptables", "-A", "INPUT", "-p", proto, "--dport", port, "-j", "DROP")
}

func unblockRule(label string) (string, string) {
	if detectBackend() == "nft" {
		return shared.RunShell(fmt.Sprintf("nft -a list chain inet %s input | grep '%s' | awk -F'#' '{print $2}' | xargs -I{} nft delete rule inet %s input handle {}", chain, label, chain))
	}
	return shared.RunShell("iptables -L INPUT --line-numbers -n | grep DROP | awk '{print $1}' | tac | xargs -I{} iptables -D INPUT {}")
}

func listRules() (string, string) {
	if detectBackend() == "nft" {
		return shared.RunShell(fmt.Sprintf("nft list table inet %s 2>/dev/null", chain))
	}
	return shared.Run("iptables", "-L", "-n", "-v")
}
