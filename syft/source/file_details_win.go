//go:build windows
// +build windows

package source

import (
	"os"
)

// GetXid is a placeholder for windows file information
func GetXid(info os.FileInfo) (uid, gid int) {
	return -1, -1
}
