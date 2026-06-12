package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/d4n5h/Wazuh-C-LR-Active-Response/internal/shared"
)

var debugFile = filepath.Join(shared.WarDir, "collect.log")

var allActions = []string{"processes", "connections", "users", "services", "autoruns"}

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
		"origin":     map[string]string{"name": "C-LR", "module": "Collect"},
		"parameters": map[string]string{"program": program},
		"clr":        clr,
	})
}

func runAction(action string) (string, string) {
	switch action {
	case "processes":
		return collectProcesses()
	case "connections":
		return collectConnections()
	case "users":
		return collectUsers()
	case "services":
		return collectServices()
	case "autoruns":
		return collectAutoruns()
	default:
		return "", fmt.Sprintf("unknown action: %s", action)
	}
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
		output("C-LR Collect", "error", "system", "", fmt.Sprintf("Input error: %v", err), dt+" C-LR Collect", 0)
		os.Exit(1)
	}

	program := input.Parameters.Program
	logHeader := dt + " " + program
	action := input.Parameters.Alert.Data.Action
	user := input.Parameters.Alert.Data.User

	if input.Parameters.Alert.Data.Debug {
		shared.Debug(debugFile, "main: "+raw)
	}
	if user == "" {
		output(program, action, user, "", "No user was provided. Please specify a user in the alert > data, for audit.", logHeader, 0)
		return
	}

	actions := []string{action}
	if action == "all" {
		actions = allActions
	} else if action == "" {
		output(program, action, user, "", "No action provided. Use: processes, connections, users, services, autoruns, all", logHeader, 0)
		return
	}

	seq := 0
	for _, a := range actions {
		stdout, stderr := runAction(a)
		for _, batch := range shared.BatchLines(stdout, 50) {
			seq++
			batch = strings.TrimSpace(batch)
			output(program, a, user, batch, stderr, logHeader, seq)
		}
	}
}
