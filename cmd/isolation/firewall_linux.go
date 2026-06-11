//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var (
	fwBackupFile  = filepath.Join(backupDir, "fw_rules.backup")
	backendFile   = filepath.Join(backupDir, "backend.type")
	isolatedMarker = filepath.Join(backupDir, ".isolated")
)

func runCmd(name string, args ...string) (string, string) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), err.Error()
	}
	return string(out), ""
}

func detectBackend() string {
	if _, err := exec.LookPath("nft"); err == nil {
		return "nftables"
	}
	return "iptables"
}

func isIsolated() bool {
	_, err := os.Stat(isolatedMarker)
	return err == nil
}

func isolate(ipException []string) (string, string) {
	if err := validateIPs(ipException); err != nil {
		return "", err.Error()
	}

	os.MkdirAll(backupDir, 0755)

	if isIsolated() {
		return "", "The device is already isolated, no action was taken."
	}

	backend := detectBackend()
	var outs, errs []string

	switch backend {
	case "nftables":
		stdout, stderr := isolateNftables(ipException)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	default:
		stdout, stderr := isolateIptables(ipException)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	}

	for _, e := range errs {
		if e != "" {
			return strings.Join(outs, " "), strings.Join(errs, " ")
		}
	}
	os.WriteFile(backendFile, []byte(backend), 0644)
	os.WriteFile(isolatedMarker, []byte("1"), 0644)

	return strings.Join(outs, " "), strings.Join(errs, " ")
}

func isolateNftables(ipException []string) (string, string) {
	var outs, errs []string

	stdout, stderr := runCmd("sh", "-c", fmt.Sprintf("nft list ruleset > %s", fwBackupFile))
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("nft", "flush", "ruleset")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("nft", "add", "table", "inet", "clr_isolate")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("sh", "-c", `nft add chain inet clr_isolate input '{ type filter hook input priority 0; policy drop; }'`)
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("sh", "-c", `nft add chain inet clr_isolate output '{ type filter hook output priority 0; policy drop; }'`)
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	for _, ip := range ipException {
		stdout, stderr = runCmd("nft", "add", "rule", "inet", "clr_isolate", "input", "ip", "saddr", ip, "accept")
		outs = append(outs, stdout)
		errs = append(errs, stderr)

		stdout, stderr = runCmd("nft", "add", "rule", "inet", "clr_isolate", "output", "ip", "daddr", ip, "accept")
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	}

	return strings.Join(outs, " "), strings.Join(errs, " ")
}

func isolateIptables(ipException []string) (string, string) {
	var outs, errs []string

	stdout, stderr := runCmd("sh", "-c", fmt.Sprintf("iptables-save > %s", fwBackupFile))
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("iptables", "-F")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("iptables", "-P", "INPUT", "DROP")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("iptables", "-P", "OUTPUT", "DROP")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("iptables", "-P", "FORWARD", "DROP")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	for _, ip := range ipException {
		stdout, stderr = runCmd("iptables", "-A", "INPUT", "-s", ip, "-j", "ACCEPT")
		outs = append(outs, stdout)
		errs = append(errs, stderr)

		stdout, stderr = runCmd("iptables", "-A", "OUTPUT", "-d", ip, "-j", "ACCEPT")
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	}

	return strings.Join(outs, " "), strings.Join(errs, " ")
}

func release() (string, string) {
	if !isIsolated() {
		return "", "The host is not isolated, or the backup has been removed."
	}

	backend, _ := os.ReadFile(backendFile)
	var outs, errs []string
	var stdout, stderr string

	switch strings.TrimSpace(string(backend)) {
	case "nftables":
		stdout, stderr = runCmd("nft", "flush", "ruleset")
		outs = append(outs, stdout)
		errs = append(errs, stderr)

		stdout, stderr = runCmd("nft", "-f", fwBackupFile)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	default:
		stdout, stderr = runCmd("sh", "-c", fmt.Sprintf("iptables-restore < %s", fwBackupFile))
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	}

	os.Remove(fwBackupFile)
	os.Remove(backendFile)
	os.Remove(isolatedMarker)

	return strings.Join(outs, " "), strings.Join(errs, " ")
}
