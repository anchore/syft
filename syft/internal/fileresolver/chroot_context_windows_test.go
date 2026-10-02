package fileresolver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// windows CI runs from D: while t.TempDir() lives on C:, so the root and cwd don't share a volume
func TestChrootContext_ToChrootPath_rootOnAnotherVolume(t *testing.T) {
	ctx := ChrootContext{
		root:              `C:\scan\root`,
		cwd:               `D:\work`,
		cwdRelativeToRoot: `C:\scan\root`,
	}
	assert.Equal(t, "dir/file.txt", ctx.ToChrootPath("/c/scan/root/dir/file.txt"))
}
