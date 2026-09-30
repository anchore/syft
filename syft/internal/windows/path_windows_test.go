package windows

import "testing"

// note: these live in a _windows file because ToPosix and FromPosix delegate to path/filepath, whose notion of a
// volume name and a separator only matches these expectations when the host is Windows.

func Test_ToPosix(t *testing.T) {
	tests := []struct {
		name        string
		windowsPath string
		want        string
	}{
		{
			name:        "basic case",
			windowsPath: `C:\some\windows\place`,
			want:        "/c/some/windows/place",
		},
		{
			name:        "escaped case",
			windowsPath: `C:\\some\\windows\\place`,
			want:        "/c/some/windows/place",
		},
		{
			name:        "forward slash",
			windowsPath: `C:/foo/bar`,
			want:        "/c/foo/bar",
		},
		{
			name:        "mix slash",
			windowsPath: `C:\foo/bar\`,
			want:        "/c/foo/bar",
		},
		{
			name:        "case sensitive case",
			windowsPath: `C:\Foo/bAr\`,
			want:        "/c/Foo/bAr",
		},
		{
			name:        "special char case",
			windowsPath: `C:\ふー\バー`,
			want:        "/c/ふー/バー",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToPosix(tt.windowsPath); got != tt.want {
				t.Errorf("ToPosix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_FromPosix(t *testing.T) {
	tests := []struct {
		name      string
		posixPath string
		want      string
	}{
		{
			name:      "basic case",
			posixPath: "/c/some/windows/place",
			want:      `C:\some\windows\place`,
		},
		{
			name:      "trailing separator",
			posixPath: "/c/foo/bar/",
			want:      `C:\foo\bar`,
		},
		{
			name:      "root of a volume",
			posixPath: "/c",
			want:      `C:\`,
		},
		{
			name:      "case is preserved below the volume",
			posixPath: "/c/Foo/bAr",
			want:      `C:\Foo\bAr`,
		},
		{
			name:      "special char case",
			posixPath: "/c/ふー/バー",
			want:      `C:\ふー\バー`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FromPosix(tt.posixPath); got != tt.want {
				t.Errorf("FromPosix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_ToPosix_FromPosix_RoundTrip(t *testing.T) {
	paths := []string{
		`C:\some\windows\place`,
		`C:\Foo\bAr`,
		`C:\ふー\バー`,
		`D:\`,
	}

	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			if got := FromPosix(ToPosix(p)); got != p {
				t.Errorf("FromPosix(ToPosix(%v)) = %v, want %v", p, got, p)
			}
		})
	}
}
