//go:build windows

package main

import "os"

func secureFile(path string) {
	os.Chmod(path, 0000)
}
