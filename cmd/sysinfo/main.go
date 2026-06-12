package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
)

var debugFile = filepath.Join(shared.WarDir, "sysinfo.log")

func output(program, user, stdout, stderr, logHeader string) {
	shared.WriteLog(logHeader, map[string]interface{}{
		"command":    "add",
		"origin":     map[string]string{"name": "C-LR", "module": "Sysinfo"},
		"parameters": map[string]string{"program": program},
		"clr": map[string]string{
			"action": "sysinfo",
			"user":   user,
			"result": fmt.Sprintf("stdout: %s\nstderr: %s", stdout, stderr),
		},
	})
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
		shared.Debug(debugFile, fmt.Sprintf("ReadInput error: %v (raw: %s)", err, raw))
		output("C-LR Sysinfo", "system", "", fmt.Sprintf("Input error: %v", err), dt+" C-LR Sysinfo")
		os.Exit(1)
	}

	program := input.Parameters.Program
	logHeader := dt + " " + program
	user := input.Parameters.Alert.Data.User

	if input.Parameters.Alert.Data.Debug {
		shared.Debug(debugFile, "main: "+raw)
	}
	if user == "" {
		output(program, user, "", "No user was provided. Please specify a user in the alert > data, for audit.", logHeader)
		return
	}

	stdout, stderr := gatherSysinfo()
	seq := 0
	for _, batch := range shared.BatchLines(stdout, 50) {
		seq++
		clr := map[string]interface{}{
			"action":   "sysinfo",
			"user":     user,
			"result":   fmt.Sprintf("stdout: %s\nstderr: %s", strings.TrimSpace(batch), stderr),
			"sequence": seq,
		}
		shared.WriteLog(logHeader, map[string]interface{}{
			"command":    "add",
			"origin":     map[string]string{"name": "C-LR", "module": "Sysinfo"},
			"parameters": map[string]string{"program": program},
			"clr":        clr,
		})
	}
}
