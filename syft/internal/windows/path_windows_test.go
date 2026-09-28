package windows

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToPosix(t *testing.T) {
	tests := map[string]string{
		`C:\some\windows\place`:    "/c/some/windows/place",
		`C:\\some\\windows\\place`: "/c/some/windows/place",
		`C:/foo/bar`:               "/c/foo/bar",
		`C:\foo/bar\`:              "/c/foo/bar",
		`C:\Foo/bAr\`:              "/c/Foo/bAr",
		`C:\ふー\バー`:                 "/c/ふー/バー",
	}
	for in, want := range tests {
		assert.Equal(t, want, ToPosix(in), in)
	}
}

func TestFromPosix(t *testing.T) {
	tests := map[string]string{
		"/c/some/windows/place": `C:\some\windows\place`,
		"/c/Foo/bAr":            `C:\Foo\bAr`,
		"/c/ふー/バー":              `C:\ふー\バー`,
	}
	for in, want := range tests {
		assert.Equal(t, want, FromPosix(in), in)
	}
}
