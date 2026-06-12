//go:build darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

var rulesFile = filepath.Join(shared.WarDir, "firewall", "clr.rules")

func ensureRulesFile() {
	os.MkdirAll(filepath.Dir(rulesFile), 0700)
	if _, err := os.Stat(rulesFile); os.IsNotExist(err) {
		os.WriteFile(rulesFile, []byte(""), 0600)
	}
}

func blockIP(ip string) (string, string) {
	ensureRulesFile()
	rule := fmt.Sprintf("block drop out quick on any proto any from any to %s # clr-block-ip-%s\n", ip, ip)
	rule += fmt.Sprintf("block drop in quick on any proto any from %s to any # clr-block-ip-%s\n", ip, ip)
	f, err := os.OpenFile(rulesFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return "", err.Error()
	}
	f.WriteString(rule)
	f.Close()
	shared.Run("pfctl", "-f", rulesFile)
	return fmt.Sprintf("blocked ip %s", ip), ""
}

func blockPort(spec string) (string, string) {
	port := spec
	proto := "tcp"
	if parts := strings.Split(spec, ":"); len(parts) == 2 {
		port, proto = parts[0], parts[1]
	}
	ensureRulesFile()
	rule := fmt.Sprintf("block drop in quick proto %s from any to any port %s # clr-block-port-%s\n", proto, port, port)
	f, err := os.OpenFile(rulesFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return "", err.Error()
	}
	f.WriteString(rule)
	f.Close()
	shared.Run("pfctl", "-f", rulesFile)
	return fmt.Sprintf("blocked port %s/%s", port, proto), ""
}

func unblockRule(label string) (string, string) {
	data, err := os.ReadFile(rulesFile)
	if err != nil {
		return "", err.Error()
	}
	var kept []string
	for _, line := range strings.Split(string(data), "\n") {
		if line == "" {
			continue
		}
		if strings.Contains(line, label) {
			continue
		}
		kept = append(kept, line)
	}
	os.WriteFile(rulesFile, []byte(strings.Join(kept, "\n")+"\n"), 0600)
	shared.Run("pfctl", "-f", rulesFile)
	return fmt.Sprintf("removed rule matching %s", label), ""
}

func listRules() (string, string) {
	data, err := os.ReadFile(rulesFile)
	if err != nil {
		if os.IsNotExist(err) {
			return "no rules", ""
		}
		return "", err.Error()
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return "no rules", ""
	}
	return string(data), ""
}
