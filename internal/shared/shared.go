package shared

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type InputJSON struct {
	Parameters Parameters `json:"parameters"`
}

type Parameters struct {
	Program   string    `json:"program"`
	ExtraArgs []string  `json:"extra_args"`
	Alert     AlertData `json:"alert"`
}

type AlertData struct {
	Data Data `json:"data"`
}

type Data struct {
	Action string `json:"action"`
	User   string `json:"user"`
	Debug  bool   `json:"debug"`
}

func LogPath() string {
	return filepath.Join(WarDir, "active-responses.log")
}

func CurrentDatetime() string {
	return time.Now().Format("2006/01/02 15:04:05")
}

func Debug(debugFile, message string) {
	f, err := os.OpenFile(debugFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, message)
}

func WriteLog(logHeader string, result interface{}) {
	data, err := json.Marshal(result)
	if err != nil {
		return
	}
	f, err := os.OpenFile(LogPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s: %s\n", logHeader, string(data))
}

func ReadInput() (InputJSON, string, error) {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64*1024), 64*1024)
	if !scanner.Scan() {
		err := scanner.Err()
		if err == nil {
			return InputJSON{}, "", fmt.Errorf("empty stdin")
		}
		return InputJSON{}, "", err
	}
	raw := strings.TrimSpace(scanner.Text())
	var input InputJSON
	if err := json.Unmarshal([]byte(raw), &input); err != nil {
		return InputJSON{}, raw, err
	}
	return input, raw, nil
}
