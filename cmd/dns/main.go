package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
)

const marker = " # C-LR"

var debugFile = filepath.Join(shared.WarDir, "dns.log")

func output(program, action, user, stdout, stderr, logHeader string) {
	shared.WriteLog(logHeader, map[string]interface{}{
		"command":    "add",
		"origin":     map[string]string{"name": "C-LR", "module": "DNS"},
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
		output("C-LR DNS", "error", "system", "", fmt.Sprintf("Input error: %v", err), dt+" C-LR DNS")
		os.Exit(1)
	}

	program := input.Parameters.Program
	logHeader := dt + " " + program
	action := input.Parameters.Alert.Data.Action
	user := input.Parameters.Alert.Data.User
	domains := input.Parameters.ExtraArgs

	if input.Parameters.Alert.Data.Debug {
		shared.Debug(debugFile, "main: "+raw)
	}
	if user == "" {
		output(program, action, user, "", "No user was provided. Please specify a user in the alert > data, for audit.", logHeader)
		return
	}

	var stdout, stderr string
	switch action {
	case "block":
		stdout, stderr = blockDomains(domains)
	case "unblock":
		stdout, stderr = unblockDomains(domains)
	case "list":
		stdout, stderr = listBlocks()
	default:
		stderr = "No action provided. Use: block, unblock, list"
	}

	stdout = strings.ReplaceAll(stdout, "\n", " ")
	stderr = strings.ReplaceAll(stderr, "\n", " ")
	output(program, action, user, stdout, stderr, logHeader)
}
