package ai

import (
	"os"

	"golang.org/x/sys/windows"
)

// markSparse sets the sparse attribute on the file. NTFS reserves disk space for the whole length of a file
// extended with Truncate unless it is sparse.
func markSparse(f *os.File) error {
	var n uint32
	return windows.DeviceIoControl(windows.Handle(f.Fd()), windows.FSCTL_SET_SPARSE, nil, 0, nil, 0, &n, nil)
}
