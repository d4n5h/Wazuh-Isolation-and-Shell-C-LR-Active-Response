package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
)

var debugFile = filepath.Join(shared.WarDir, "log-collect.log")

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
		"origin":     map[string]string{"name": "C-LR", "module": "LogCollect"},
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
		output("C-LR LogCollect", "error", "system", "", fmt.Sprintf("Input error: %v", err), dt+" C-LR LogCollect", 0)
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
	case "evtlog":
		if len(args) < 1 {
			stderr = "extra_args[0] must be event channel (e.g. Security)"
		} else {
			count := "50"
			if len(args) > 1 {
				count = args[1]
			}
			stdout, stderr = collectEvtLog(args[0], count)
		}
	case "journal":
		if len(args) < 1 {
			stderr = "extra_args[0] must be systemd unit"
		} else {
			count := "50"
			if len(args) > 1 {
				count = args[1]
			}
			stdout, stderr = collectJournal(args[0], count)
		}
	case "file":
		if len(args) < 1 {
			stderr = "extra_args[0] must be log file path"
		} else {
			count := "50"
			if len(args) > 1 {
				count = args[1]
			}
			stdout, stderr = collectFile(args[0], count)
		}
	default:
		stderr = "No action provided. Use: evtlog, journal, file"
	}

	seq := 0
	for _, batch := range shared.BatchLines(stdout, 50) {
		seq++
		output(program, action, user, strings.TrimSpace(batch), stderr, logHeader, seq)
	}
	if seq == 0 {
		output(program, action, user, stdout, stderr, logHeader, 0)
	}
}
