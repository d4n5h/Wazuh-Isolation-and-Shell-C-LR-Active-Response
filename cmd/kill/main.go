package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

var debugFile = filepath.Join(shared.WarDir, "kill.log")

func output(program, action, target, user, stdout, stderr, logHeader string) {
	shared.WriteLog(logHeader, map[string]interface{}{
		"command":    "add",
		"origin":     map[string]string{"name": "C-LR", "module": "Kill"},
		"parameters": map[string]string{"program": program},
		"clr": map[string]string{
			"action": fmt.Sprintf("%s: %s", action, target),
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
		output("C-LR Kill", "error", "", "system", "", fmt.Sprintf("Input error: %v", err), dt+" C-LR Kill")
		os.Exit(1)
	}

	program := input.Parameters.Program
	logHeader := dt + " " + program
	action := input.Parameters.Alert.Data.Action
	user := input.Parameters.Alert.Data.User
	target := ""
	if len(input.Parameters.ExtraArgs) > 0 {
		target = input.Parameters.ExtraArgs[0]
	}

	if input.Parameters.Alert.Data.Debug {
		shared.Debug(debugFile, "main: "+raw)
	}
	if user == "" {
		output(program, action, target, user, "", "No user was provided. Please specify a user in the alert > data, for audit.", logHeader)
		return
	}
	if target == "" {
		output(program, action, target, user, "", "No target provided in extra_args (PID or process name).", logHeader)
		return
	}

	tree := action == "tree"
	stdout, stderr := killProcess(target, tree)
	stdout = strings.ReplaceAll(stdout, "\n", " ")
	stderr = strings.ReplaceAll(stderr, "\n", " ")
	output(program, action, target, user, stdout, stderr, logHeader)
}
