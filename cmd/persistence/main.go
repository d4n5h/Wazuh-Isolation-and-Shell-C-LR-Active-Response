package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
)

var debugFile = filepath.Join(shared.WarDir, "persistence.log")

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
		"origin":     map[string]string{"name": "C-LR", "module": "Persistence"},
		"parameters": map[string]string{"program": program},
		"clr":        clr,
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
		output("C-LR Persistence", "error", "system", "", fmt.Sprintf("Input error: %v", err), dt+" C-LR Persistence", 0)
		os.Exit(1)
	}

	program := input.Parameters.Program
	logHeader := dt + " " + program
	action := input.Parameters.Alert.Data.Action
	user := input.Parameters.Alert.Data.User
	args := input.Parameters.ExtraArgs

	if input.Parameters.Alert.Data.Debug {
		shared.Debug(debugFile, "main: "+raw)
	}
	if user == "" {
		output(program, action, user, "", "No user was provided. Please specify a user in the alert > data, for audit.", logHeader, 0)
		return
	}

	var stdout, stderr string
	switch action {
	case "scan":
		stdout, stderr = scanPersistence()
		seq := 0
		for _, batch := range shared.BatchLines(stdout, 50) {
			seq++
			output(program, action, user, strings.TrimSpace(batch), stderr, logHeader, seq)
		}
		if seq == 0 {
			output(program, action, user, stdout, stderr, logHeader, 0)
		}
	case "remove":
		if len(args) < 2 {
			output(program, action, user, "", "extra_args must be [type, identifier]", logHeader, 0)
			return
		}
		stdout, stderr = removePersistence(args[0], args[1])
		stdout = strings.ReplaceAll(stdout, "\n", " ")
		stderr = strings.ReplaceAll(stderr, "\n", " ")
		output(program, action, user, stdout, stderr, logHeader, 0)
	default:
		output(program, action, user, "", "No action provided. Use: scan, remove", logHeader, 0)
	}
}
