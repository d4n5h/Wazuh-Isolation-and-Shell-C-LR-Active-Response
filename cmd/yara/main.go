package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

var debugFile = filepath.Join(shared.WarDir, "yara.log")

func output(program, action, user, stdout, stderr, logHeader string, seq int) {
	clr := map[string]interface{}{
		"action": action,
		"user":   user,
		"result": fmt.Sprintf("stdout: %s\nstderr: %s", stdout, stderr),
	}
	if seq > 0 {
		clr["sequence"] = seq
	}
	shared.WriteLog(logHeader, map[string]interface{}{
		"command":    "add",
		"origin":     map[string]string{"name": "C-LR", "module": "Yara"},
		"parameters": map[string]string{"program": program},
		"clr":        clr,
	})
}

func yaraScan(target, rulesPath string) (string, string) {
	if _, err := exec.LookPath("yara"); err != nil {
		return "", "yara CLI not found in PATH"
	}
	if rulesPath == "" {
		return "", "alert.data.action must specify rules file path"
	}
	if target == "" {
		return "", "extra_args[0] must be scan target path"
	}
	return shared.Run("yara", "-r", rulesPath, target)
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			shared.Debug(debugFile, fmt.Sprintf("PANIC: %v", r))
		}
	}()

	input, raw, err := shared.ReadInput()
	dt := shared.CurrentDatetime()
	if err != nil {
		output("C-LR Yara", "error", "system", "", fmt.Sprintf("Input error: %v", err), dt+" C-LR Yara", 0)
		os.Exit(1)
	}

	program := input.Parameters.Program
	logHeader := dt + " " + program
	rulesPath := input.Parameters.Alert.Data.Action
	user := input.Parameters.Alert.Data.User
	target := ""
	if len(input.Parameters.ExtraArgs) > 0 {
		target = input.Parameters.ExtraArgs[0]
	}

	if input.Parameters.Alert.Data.Debug {
		shared.Debug(debugFile, "main: "+raw)
	}
	if user == "" {
		output(program, rulesPath, user, "", "No user was provided. Please specify a user in the alert > data, for audit.", logHeader, 0)
		return
	}

	stdout, stderr := yaraScan(target, rulesPath)
	seq := 0
	for _, batch := range shared.BatchLines(stdout, 50) {
		seq++
		output(program, rulesPath, user, strings.TrimSpace(batch), stderr, logHeader, seq)
	}
	if seq == 0 {
		output(program, rulesPath, user, stdout, stderr, logHeader, 0)
	}
}
