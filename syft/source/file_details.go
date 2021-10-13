//go:build linux || darwin
// +build linux darwin

package source

import (
	"os"
	"syscall"
)

// GetXid is the UID GID system info for unix
func GetXid(info os.FileInfo) (uid, gid int) {
	uid = -1
	gid = -1
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		uid = int(stat.Uid)
		gid = int(stat.Gid)
	}

	return uid, gid
}
