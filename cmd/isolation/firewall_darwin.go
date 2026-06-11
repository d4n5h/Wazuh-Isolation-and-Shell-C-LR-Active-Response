//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const pfConf = "/etc/pf.conf"

var (
	fwBackupFile   = filepath.Join(backupDir, "pf.conf.backup")
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

	var outs, errs []string

	stdout, stderr := runCmd("cp", pfConf, fwBackupFile)
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	var rules strings.Builder
	rules.WriteString("block all\n")
	for _, ip := range ipException {
		rules.WriteString(fmt.Sprintf("pass in from %s\n", ip))
		rules.WriteString(fmt.Sprintf("pass out to %s\n", ip))
	}

	if err := os.WriteFile(pfConf, []byte(rules.String()), 0644); err != nil {
		return "", err.Error()
	}

	stdout, stderr = runCmd("pfctl", "-f", pfConf)
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("pfctl", "-e")
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	os.WriteFile(isolatedMarker, []byte("1"), 0644)

	return strings.Join(outs, " "), strings.Join(errs, " ")
}

func release() (string, string) {
	if !isIsolated() {
		return "", "The host is not isolated, or the backup has been removed."
	}

	var outs, errs []string

	stdout, stderr := runCmd("cp", fwBackupFile, pfConf)
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	stdout, stderr = runCmd("pfctl", "-f", pfConf)
	outs = append(outs, stdout)
	errs = append(errs, stderr)

	os.Remove(fwBackupFile)
	os.Remove(isolatedMarker)

	return strings.Join(outs, " "), strings.Join(errs, " ")
}
