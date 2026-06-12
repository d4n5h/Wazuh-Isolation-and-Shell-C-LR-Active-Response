package main

import (
	"crypto/md5"
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

var debugFile = filepath.Join(shared.WarDir, "hash.log")

type HashResult struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	MD5    string `json:"md5"`
	Size   int64  `json:"size"`
	Error  string `json:"error,omitempty"`
}

func hashFile(path string) HashResult {
	r := HashResult{Path: path}
	f, err := os.Open(path)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	defer f.Close()
	h256 := sha256.New()
	hmd5 := md5.New()
	w := io.MultiWriter(h256, hmd5)
	n, err := io.Copy(w, f)
	if err != nil {
		r.Error = err.Error()
		return r
	}
	r.Size = n
	r.SHA256 = hex.EncodeToString(h256.Sum(nil))
	r.MD5 = hex.EncodeToString(hmd5.Sum(nil))
	return r
}

func output(program, user, stdout, stderr, logHeader string) {
	shared.WriteLog(logHeader, map[string]interface{}{
		"command":    "add",
		"origin":     map[string]string{"name": "C-LR", "module": "Hash"},
		"parameters": map[string]string{"program": program},
		"clr": map[string]string{
			"action": "hash",
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
		output("C-LR Hash", "system", "", fmt.Sprintf("Input error: %v", err), dt+" C-LR Hash")
		os.Exit(1)
	}

	program := input.Parameters.Program
	logHeader := dt + " " + program
	user := input.Parameters.Alert.Data.User
	paths := input.Parameters.ExtraArgs

	if input.Parameters.Alert.Data.Debug {
		shared.Debug(debugFile, "main: "+raw)
	}
	if user == "" {
		output(program, user, "", "No user was provided. Please specify a user in the alert > data, for audit.", logHeader)
		return
	}
	if len(paths) == 0 {
		output(program, user, "", "No file paths provided in extra_args.", logHeader)
		return
	}

	var results []HashResult
	for _, p := range paths {
		results = append(results, hashFile(p))
	}
	data, _ := json.Marshal(results)
	stdout := strings.ReplaceAll(string(data), "\n", " ")
	output(program, user, stdout, "", logHeader)
}
