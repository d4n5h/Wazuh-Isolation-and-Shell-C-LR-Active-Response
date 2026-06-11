//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

var fwRulesFile = filepath.Join(backupDir, "fw_rules.xml")

func runCmd(args ...string) (string, string) {
	cmd := exec.Command("cmd", append([]string{"/c"}, args...)...)
	out, err := cmd.Output()
	stderr := ""
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
		} else {
			stderr = err.Error()
		}
	}
	return string(out), stderr
}

func isolate(ipException []string) (string, string) {
	if err := validateIPs(ipException); err != nil {
		return "", err.Error()
	}

	os.MkdirAll(backupDir, 0755)

	if _, err := os.Stat(fwRulesFile); err == nil {
		return "", "The device is already isolated, no action was taken."
	}

	var outs, errs []string

	stdout, stderr := runCmd("netsh", "advfirewall", "export", fwRulesFile)
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=all")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("netsh", "advfirewall", "firewall", "set", "rule", "name=all", "new", "enable=no")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("netsh", "advfirewall", "set", "allprofiles", "state", "on")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	for _, ip := range ipException {
		stdout, stderr = runCmd("netsh", "advfirewall", "firewall", "add", "rule",
			"name=allow-siem-in", "dir=in", "action=allow", "protocol=any", "remoteip="+ip)
		outs = append(outs, stdout)
		errs = append(errs, stderr)

		stdout, stderr = runCmd("netsh", "advfirewall", "firewall", "add", "rule",
			"name=allow-siem-out", "dir=out", "action=allow", "protocol=any", "remoteip="+ip)
		outs = append(outs, stdout)
		errs = append(errs, stderr)
	}

	return strings.Join(outs, " "), strings.Join(errs, " ")
}

func release() (string, string) {
	if _, err := os.Stat(fwRulesFile); err == nil {
		stdout, stderr := runCmd("netsh", "advfirewall", "import", fwRulesFile)
		os.Remove(fwRulesFile)
		return stdout, stderr
	}
	return "", "The host is not isolated, or the backup has been removed."
}
