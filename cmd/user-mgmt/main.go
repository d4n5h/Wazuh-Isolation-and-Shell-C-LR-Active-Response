package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

var debugFile = filepath.Join(shared.WarDir, "user-mgmt.log")

func output(program, action, user, stdout, stderr, logHeader string) {
	shared.WriteLog(logHeader, map[string]interface{}{
		"command":    "add",
		"origin":     map[string]string{"name": "C-LR", "module": "UserMgmt"},
		"parameters": map[string]string{"program": program},
		"clr": map[string]string{
			"action": action,
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
		output("C-LR UserMgmt", "error", "system", "", fmt.Sprintf("Input error: %v", err), dt+" C-LR UserMgmt")
		os.Exit(1)
	}

	program := input.Parameters.Program
	logHeader := dt + " " + program
	action := input.Parameters.Alert.Data.Action
	analyst := input.Parameters.Alert.Data.User
	target := ""
	if len(input.Parameters.ExtraArgs) > 0 {
		target = input.Parameters.ExtraArgs[0]
	}

	if input.Parameters.Alert.Data.Debug {
		shared.Debug(debugFile, "main: "+raw)
	}
	if analyst == "" {
		output(program, action, analyst, "", "No user was provided. Please specify a user in the alert > data, for audit.", logHeader)
		return
	}
	if target == "" && action != "logoff" {
		output(program, action, analyst, "", "extra_args[0] must be target username", logHeader)
		return
	}

	stdout, stderr := userAction(action, target)
	stdout = strings.ReplaceAll(stdout, "\n", " ")
	stderr = strings.ReplaceAll(stderr, "\n", " ")
	output(program, action, analyst, stdout, stderr, logHeader)
}
