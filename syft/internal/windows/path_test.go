package windows

import (
	"testing"
)

func TestAppendRootTerminator(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		expect string
	}{
		{
			name:   "NormalUNC",
			path:   "\\\\localhost\\myserver\\",
			expect: "\\\\localhost\\myserver\\\\",
		},
		{
			name:   "DriveUNC",
			path:   "\\\\localhost\\C$\\",
			expect: "\\\\localhost\\C$\\\\",
		},
		{
			name:   "DriveC",
			path:   "C",
			expect: "C:\\",
		},
		{
			name:   "DriveC2",
			path:   "C:",
			expect: "C:\\",
		},
		{
			name:   "DriveC\\",
			path:   "C:\\",
			expect: "C:\\",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AppendRootTerminator(tt.path)
			if got != tt.expect {
				t.Errorf("FromPosix() got = %v, expects %v", got, tt.expect)
			}
		})
	}
}
