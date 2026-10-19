package ai

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// fileStandardInfo mirrors FILE_STANDARD_INFO, which golang.org/x/sys/windows does not define.
type fileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  bool
	Directory      bool
}

func TestExtendToModelSize_doesNotReserveDiskOnWindows(t *testing.T) {
	const size = 1 << 30
	f, err := os.Create(filepath.Join(t.TempDir(), "header.gguf"))
	require.NoError(t, err)
	defer f.Close()
	_, err = f.Write(make([]byte, 4096))
	require.NoError(t, err)

	require.NoError(t, extendToModelSize(f, size))

	var info fileStandardInfo
	require.NoError(t, windows.GetFileInformationByHandleEx(windows.Handle(f.Fd()), windows.FileStandardInfo,
		(*byte)(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))))
	assert.Equal(t, int64(size), info.EndOfFile)
	// a non-sparse file would have the whole length allocated
	assert.Less(t, info.AllocationSize, int64(16<<20))
}
