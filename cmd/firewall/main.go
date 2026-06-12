package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
)

var debugFile = filepath.Join(shared.WarDir, "firewall.log")

func output(program, action, user, stdout, stderr, logHeader string) {
	shared.WriteLog(logHeader, map[string]interface{}{
		"command":    "add",
		"origin":     map[string]string{"name": "C-LR", "module": "Firewall"},
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
		output("C-LR Firewall", "error", "system", "", fmt.Sprintf("Input error: %v", err), dt+" C-LR Firewall")
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
		output(program, action, user, "", "No user was provided. Please specify a user in the alert > data, for audit.", logHeader)
		return
	}

	var stdout, stderr string
	switch action {
	case "block-ip":
		if len(args) < 1 {
			stderr = "extra_args[0] must be IP/CIDR"
		} else {
			stdout, stderr = blockIP(args[0])
		}
	case "block-port":
		if len(args) < 1 {
			stderr = "extra_args[0] must be port[:proto] (e.g. 443:tcp)"
		} else {
			stdout, stderr = blockPort(args[0])
		}
	case "unblock":
		if len(args) < 1 {
			stderr = "extra_args[0] must be rule label"
		} else {
			stdout, stderr = unblockRule(args[0])
		}
	case "list":
		stdout, stderr = listRules()
	default:
		stderr = "No action provided. Use: block-ip, block-port, unblock, list"
	}

	stdout = strings.ReplaceAll(stdout, "\n", " ")
	stderr = strings.ReplaceAll(stderr, "\n", " ")
	output(program, action, user, stdout, stderr, logHeader)
}
