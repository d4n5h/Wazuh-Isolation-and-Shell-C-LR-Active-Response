//go:build darwin

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
)

const hostsFile = "/etc/hosts"

func readHosts() (string, error) {
	data, err := os.ReadFile(hostsFile)
	return string(data), err
}

func writeHosts(content string) error {
	return os.WriteFile(hostsFile, []byte(content), 0644)
}

func flushDNS() {
	shared.RunShell("dscacheutil -flushcache; killall -HUP mDNSResponder 2>/dev/null")
}

func blockDomains(domains []string) (string, string) {
	content, err := readHosts()
	if err != nil {
		return "", err.Error()
	}
	added := 0
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" || strings.Contains(content, d+marker) {
			continue
		}
		content += fmt.Sprintf("127.0.0.1 %s%s\n", d, marker)
		added++
	}
	if added == 0 {
		return "no new domains blocked", ""
	}
	if err := writeHosts(content); err != nil {
		return "", err.Error()
	}
	flushDNS()
	return fmt.Sprintf("blocked %d domain(s)", added), ""
}

func unblockDomains(domains []string) (string, string) {
	content, err := readHosts()
	if err != nil {
		return "", err.Error()
	}
	lines := strings.Split(content, "\n")
	var kept []string
	removed := 0
	for _, line := range lines {
		if strings.Contains(line, marker) {
			if len(domains) == 0 {
				removed++
				continue
			}
			skip := false
			for _, d := range domains {
				if strings.Contains(line, d) {
					skip = true
					removed++
					break
				}
			}
			if skip {
				continue
			}
		}
		kept = append(kept, line)
	}
	if err := writeHosts(strings.Join(kept, "\n")); err != nil {
		return "", err.Error()
	}
	flushDNS()
	return fmt.Sprintf("removed %d block(s)", removed), ""
}

func listBlocks() (string, string) {
	content, err := readHosts()
	if err != nil {
		return "", err.Error()
	}
	var blocks []string
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, marker) {
			blocks = append(blocks, strings.TrimSpace(line))
		}
	}
	if len(blocks) == 0 {
		return "no blocked domains", ""
	}
	return strings.Join(blocks, "; "), ""
}
