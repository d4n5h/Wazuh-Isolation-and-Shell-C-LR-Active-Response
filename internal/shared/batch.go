package shared

import "strings"

func BatchLines(text string, size int) []string {
	if size <= 0 {
		size = 50
	}
	lines := strings.Split(text, "\n")
	var batches []string
	for i := 0; i < len(lines); i += size {
		end := i + size
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
