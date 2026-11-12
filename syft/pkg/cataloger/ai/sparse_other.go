//go:build !windows

package ai

import "os"

// markSparse is a no-op: the filesystems syft runs on elsewhere leave the range a file is extended by with
// Truncate as a hole.
func markSparse(_ *os.File) error {
	return nil
}
