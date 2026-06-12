package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

var (
	debugFile    = filepath.Join(shared.WarDir, "quarantine.log")
	quarantineDir = filepath.Join(shared.WarDir, "quarantine")
)

type Meta struct {
	OriginalPath  string `json:"original_path"`
	SHA256        string `json:"sha256"`
	QuarantinedAt string `json:"quarantined_at"`
	User          string `json:"user"`
	Size          int64  `json:"size"`
	ID            string `json:"id"`
}

func output(program, action, user, stdout, stderr, logHeader string) {
	shared.WriteLog(logHeader, map[string]interface{}{
		"command":    "add",
		"origin":     map[string]string{"name": "C-LR", "module": "Quarantine"},
		"parameters": map[string]string{"program": program},
		"clr": map[string]string{
			"action": action,
			"user":   user,
			"result": fmt.Sprintf("stdout: %s\nstderr: %s", stdout, stderr),
		},
	})
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func metaPath(id string) string {
	return filepath.Join(quarantineDir, id+".json")
}

func doQuarantine(path, user string) (string, string) {
	if err := os.MkdirAll(quarantineDir, 0700); err != nil {
		return "", err.Error()
	}
	hash, size, err := hashFile(path)
	if err != nil {
		return "", err.Error()
	}
	id := hash[:16]
	dest := filepath.Join(quarantineDir, id)
	if err := os.Rename(path, dest); err != nil {
		return "", err.Error()
	}
	secureFile(dest)
	meta := Meta{
		OriginalPath:  path,
		SHA256:        hash,
		QuarantinedAt: time.Now().Format("2006/01/02 15:04:05"),
		User:          user,
		Size:          size,
		ID:            id,
	}
	data, _ := json.MarshalIndent(meta, "", "  ")
	if err := os.WriteFile(metaPath(id), data, 0600); err != nil {
		return "", err.Error()
	}
	return fmt.Sprintf("quarantined %s -> %s", path, id), ""
}

func doRestore(id string) (string, string) {
	data, err := os.ReadFile(metaPath(id))
	if err != nil {
		return "", err.Error()
	}
	var meta Meta
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", err.Error()
	}
	src := filepath.Join(quarantineDir, id)
	if err := os.Rename(src, meta.OriginalPath); err != nil {
		return "", err.Error()
	}
	os.Remove(metaPath(id))
	return fmt.Sprintf("restored %s -> %s", id, meta.OriginalPath), ""
}

func doDelete(id string) (string, string) {
	src := filepath.Join(quarantineDir, id)
	if err := os.Remove(src); err != nil && !os.IsNotExist(err) {
		return "", err.Error()
	}
	os.Remove(metaPath(id))
	return fmt.Sprintf("deleted quarantine entry %s", id), ""
}

func doList() (string, string) {
	entries, err := os.ReadDir(quarantineDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "no quarantined files", ""
		}
		return "", err.Error()
	}
	var lines []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(quarantineDir, e.Name()))
		if err != nil {
			continue
		}
		lines = append(lines, string(data))
	}
	if len(lines) == 0 {
		return "no quarantined files", ""
	}
	return strings.Join(lines, "\n"), ""
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
		output("C-LR Quarantine", "error", "system", "", fmt.Sprintf("Input error: %v", err), dt+" C-LR Quarantine")
		os.Exit(1)
	}

	program := input.Parameters.Program
	logHeader := dt + " " + program
	action := input.Parameters.Alert.Data.Action
	user := input.Parameters.Alert.Data.User
	arg := ""
	if len(input.Parameters.ExtraArgs) > 0 {
		arg = input.Parameters.ExtraArgs[0]
	}

	if input.Parameters.Alert.Data.Debug {
		shared.Debug(debugFile, "main: "+raw)
	}
	if user == "" {
		output(program, action, user, "", "No user was provided. Please specify a user in the alert > data, for audit.", logHeader)
		return
	}

	var stdout, stderr string
	switch action {
	case "quarantine":
		if arg == "" {
			stderr = "extra_args[0] must be file path"
		} else {
			stdout, stderr = doQuarantine(arg, user)
		}
	case "restore", "delete":
		if arg == "" {
			stderr = "extra_args[0] must be quarantine ID"
		} else if action == "restore" {
			stdout, stderr = doRestore(arg)
		} else {
			stdout, stderr = doDelete(arg)
		}
	case "list":
		stdout, stderr = doList()
	default:
		stderr = "No action provided. Use: quarantine, restore, delete, list"
	}

	stdout = strings.ReplaceAll(stdout, "\n", " ")
	stderr = strings.ReplaceAll(stderr, "\n", " ")
	output(program, action, user, stdout, stderr, logHeader)
}
