package source

import "testing"

func Test_windowsToPosix(t *testing.T) {
	type args struct {
		windowsPath string
	}
	tests := []struct {
		name          string
		args          args
		wantPosixPath string
	}{
		{
			name: "basic case",
			args: args{
				windowsPath: `C:\some\windows\place`,
			},
			wantPosixPath: "/c/some/windows/place",
		},
		{
			name: "escaped case",
			args: args{
				windowsPath: `C:\\some\\windows\\place`,
			},
			wantPosixPath: "/c/some/windows/place",
		},
		{
			name: "forward slash",
			args: args{
				windowsPath: `C:/foo/bar`,
			},
			wantPosixPath: "/c/foo/bar",
		},
		{
			name: "mix slash",
			args: args{
				windowsPath: `C:\foo/bar\`,
			},
			wantPosixPath: "/c/foo/bar",
		},
		{
			name: "random case",
			args: args{
				windowsPath: `C:\Foo/bAr\`,
			},
			wantPosixPath: "/c/Foo/bAr",
		},
		{
			name: "random case",
			args: args{
				windowsPath: `C:\ふー\バー`,
			},
			wantPosixPath: "/c/ふー/バー",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotPosixPath := windowsToPosix(tt.args.windowsPath); gotPosixPath != tt.wantPosixPath {
				t.Errorf("windowsToPosix() = %v, want %v", gotPosixPath, tt.wantPosixPath)
			}
		})
	}
}

func Test_posixToWindows(t *testing.T) {
	type args struct {
		posixPath string
	}
	tests := []struct {
		name            string
		args            args
		wantWindowsPath string
	}{
		{
			name: "basic case",
			args: args{
				posixPath: "/c/some/windows/place",
			},
			wantWindowsPath: `C:\some\windows\place`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if gotWindowsPath := posixToWindows(tt.args.posixPath); gotWindowsPath != tt.wantWindowsPath {
				t.Errorf("posixToWindows() = %v, want %v", gotWindowsPath, tt.wantWindowsPath)
			}
		})
	}
}
