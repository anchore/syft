// +build windows
package source

import (
	"os"
)

// GetXid ...
func GetXid(info os.FileInfo) (uid, gid int) {
	return -1, -1
}
