//go:build linux || darwin

package main

import "os"

func secureFile(path string) {
	os.Chmod(path, 0000)
}
