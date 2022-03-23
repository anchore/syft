//go:build windows
// +build windows

package source

import (
	"os"
)

// getFileXid is a placeholder for windows file information
func getFileXid(info os.FileInfo) (uid, gid int) {
	return -1, -1
}
