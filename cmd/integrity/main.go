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

	"github.com/d4n5h/Wazuh-Isolation-and-Shell-C-LR-Active-Response/internal/shared"
)

var (
	debugFile     = filepath.Join(shared.WarDir, "integrity.log")
	integrityDir  = filepath.Join(shared.WarDir, "integrity")
)

type FileHash struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Baseline struct {
	Label     string     `json:"label"`
	Root      string     `json:"root"`
	CreatedAt string     `json:"created_at"`
	Files     []FileHash `json:"files"`
}

func hashFile(path string) (FileHash, error) {
	f, err := os.Open(path)
	if err != nil {
		return FileHash{}, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return FileHash{}, err
	}
	return FileHash{Path: path, SHA256: hex.EncodeToString(h.Sum(nil)), Size: n}, nil
}

func walkAndHash(root string) ([]FileHash, error) {
	var files []FileHash
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		fh, err := hashFile(path)
		if err != nil {
			return nil
		}
		files = append(files, fh)
		return nil
	})
	return files, err
}

func baselinePath(label string) string {
	return filepath.Join(integrityDir, label+".json")
}

func doBaseline(label, root string) (string, string) {
	if label == "" || root == "" {
		return "", "extra_args must be [label, root_path]"
	}
	os.MkdirAll(integrityDir, 0700)
	files, err := walkAndHash(root)
	if err != nil {
		return "", err.Error()
	}
	bl := Baseline{
		Label:     label,
		Root:      root,
		CreatedAt: shared.CurrentDatetime(),
		Files:     files,
	}
	data, _ := json.MarshalIndent(bl, "", "  ")
	if err := os.WriteFile(baselinePath(label), data, 0600); err != nil {
		return "", err.Error()
	}
	return fmt.Sprintf("baseline %s saved (%d files)", label, len(files)), ""
}

func doCheck(label string) (string, string) {
	data, err := os.ReadFile(baselinePath(label))
	if err != nil {
		return "", err.Error()
	}
	var bl Baseline
	if err := json.Unmarshal(data, &bl); err != nil {
		return "", err.Error()
	}
	current, err := walkAndHash(bl.Root)
	if err != nil {
		return "", err.Error()
	}
	oldMap := map[string]FileHash{}
	for _, f := range bl.Files {
		oldMap[f.Path] = f
	}
	newMap := map[string]FileHash{}
	for _, f := range current {
		newMap[f.Path] = f
	}
	var added, modified, deleted []string
	for p, f := range newMap {
		if old, ok := oldMap[p]; !ok {
			added = append(added, p)
		} else if old.SHA256 != f.SHA256 {
			modified = append(modified, p)
		}
	}
	for p := range oldMap {
		if _, ok := newMap[p]; !ok {
			deleted = append(deleted, p)
		}
	}
	result := map[string]interface{}{
		"label":    label,
		"added":    added,
		"modified": modified,
		"deleted":  deleted,
	}
	out, _ := json.Marshal(result)
	return string(out), ""
}

func output(program, action, user, stdout, stderr, logHeader string) {
	shared.WriteLog(logHeader, map[string]interface{}{
		"command":    "add",
		"origin":     map[string]string{"name": "C-LR", "module": "Integrity"},
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
		output("C-LR Integrity", "error", "system", "", fmt.Sprintf("Input error: %v", err), dt+" C-LR Integrity")
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
	case "baseline":
		label, root := "", ""
		if len(args) > 0 {
			label = args[0]
		}
		if len(args) > 1 {
			root = args[1]
		}
		stdout, stderr = doBaseline(label, root)
	case "check":
		label := ""
		if len(args) > 0 {
			label = args[0]
		}
		if label == "" {
			stderr = "extra_args[0] must be baseline label"
		} else {
			stdout, stderr = doCheck(label)
		}
	default:
		stderr = "No action provided. Use: baseline, check"
	}

	stdout = strings.ReplaceAll(stdout, "\n", " ")
	stderr = strings.ReplaceAll(stderr, "\n", " ")
	output(program, action, user, stdout, stderr, logHeader)
}
