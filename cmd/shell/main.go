package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

var debugFile = filepath.Join(shared.WarDir, "shell.log")

type OutputResult struct {
	Command    string                 `json:"command"`
	Origin     map[string]string      `json:"origin"`
	Parameters map[string]string      `json:"parameters"`
	CLR        map[string]interface{} `json:"clr"`
}

func output(program, commandline, user string, results []string, stderr, logHeader string) {
	for i, batch := range results {
		result := OutputResult{
			Command:    "add",
			Origin:     map[string]string{"name": "C-LR", "module": "Shell"},
			Parameters: map[string]string{"program": program},
			CLR: map[string]interface{}{
				"action":   fmt.Sprintf("commandline: %s", commandline),
				"user":     user,
				"result":   fmt.Sprintf("stdout: %s\nstderr: %s", batch, stderr),
				"sequence": i + 1,
			},
		}
		shared.WriteLog(logHeader, result)
	}
}

func parse(stdout string, batchSize int) []string {
	lines := strings.Split(stdout, "\n")
	var batches []string
	for i := 0; i < len(lines); i += batchSize {
		end := i + batchSize
		if end > len(lines) {
			end = len(lines)
		}
		batches = append(batches, strings.Join(lines[i:end], "\n"))
	}
	if len(batches) == 0 {
		batches = []string{""}
	}
	return batches
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
		output("C-LR Shell", "", "system", []string{""}, fmt.Sprintf("Input error: %v", err), dt+" C-LR Shell")
		os.Exit(1)
	}

	program := input.Parameters.Program
	logHeader := dt + " " + program

	commandline := ""
	if len(input.Parameters.ExtraArgs) > 0 {
		commandline = input.Parameters.ExtraArgs[0]
	}
	user := input.Parameters.Alert.Data.User
	debugMode := input.Parameters.Alert.Data.Debug

	if debugMode {
		shared.Debug(debugFile, "main: "+raw)
	}

	if user == "" {
		output(program, commandline, user, []string{"Command was not executed"}, "No user was provided. Please specify a user in the alert > data, for audit.", logHeader)
		return
	}

	stdout, stderr := cmdRun(commandline)

	if stderr != "" {
		stdout = "error"
	}
	if stdout == "" && stderr == "" {
		stdout = "Command executed successfully"
	}

	results := parse(stdout, 50)
	output(program, commandline, user, results, stderr, logHeader)
}
