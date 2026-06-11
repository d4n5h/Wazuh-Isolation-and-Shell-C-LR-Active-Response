package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/c137labs/c-liveresponse/internal/shared"
)

var (
	debugFile = filepath.Join(shared.WarDir, "isolation.log")
	backupDir = filepath.Join(shared.WarDir, "backup")
)

type OutputResult struct {
	Command    string            `json:"command"`
	Origin     map[string]string `json:"origin"`
	Parameters map[string]string `json:"parameters"`
	CLR        map[string]string `json:"clr"`
}

func output(program, action, user, stdout, stderr, logHeader string) {
	result := OutputResult{
		Command:    "add",
		Origin:     map[string]string{"name": "C-LR", "module": "Isolation"},
		Parameters: map[string]string{"program": program},
		CLR: map[string]string{
			"action": action,
			"user":   user,
			"result": fmt.Sprintf("stdout: %s\nstderr: %s", stdout, stderr),
		},
	}
	shared.WriteLog(logHeader, result)
}

func isValidIP(ip string) bool {
	if net.ParseIP(ip) != nil {
		return true
	}
	_, _, err := net.ParseCIDR(ip)
	return err == nil
}

func validateIPs(ips []string) error {
	for _, ip := range ips {
		if !isValidIP(ip) {
			return fmt.Errorf("one or more IP addresses are invalid")
		}
	}
	return nil
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
		output("C-LR Isolation", "error", "system", "", fmt.Sprintf("Input error: %v", err), dt+" C-LR Isolation")
		os.Exit(1)
	}

	program := input.Parameters.Program
	logHeader := dt + " " + program
	ipException := input.Parameters.ExtraArgs
	action := input.Parameters.Alert.Data.Action
	user := input.Parameters.Alert.Data.User
	debugMode := input.Parameters.Alert.Data.Debug

	if debugMode {
		shared.Debug(debugFile, "main: "+raw)
	}

	if user == "" {
		output(program, action, user, "", "No user was provided. Please specify a user in the alert > data, for audit.", logHeader)
		return
	}

	switch action {
	case "isolate":
		stdout, stderr := isolate(ipException)
		stdout = strings.ReplaceAll(stdout, "\n", " ")
		stderr = strings.ReplaceAll(stderr, "\n", " ")
		output(program, action, user, stdout, stderr, logHeader)
	case "release":
		stdout, stderr := release()
		stdout = strings.ReplaceAll(stdout, "\n", " ")
		stderr = strings.ReplaceAll(stderr, "\n", " ")
		output(program, action, user, stdout, stderr, logHeader)
	default:
		output(program, action, user, "", "No action was provided. Please specify an action in the alert [isolate, release] > data.", logHeader)
	}
}
