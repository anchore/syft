package fileresolver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_resolveLinkWithinArchive pins the frame a link entry is resolved in: the archive's own root,
// never the host filesystem. An archive's link targets are attacker-supplied text, so a target
// naming the host must land inside this archive or nowhere.
func Test_resolveLinkWithinArchive(t *testing.T) {
	tests := []struct {
		name     string
		linkPath string
		linkname string
		hardLink bool
		want     string
	}{
		{
			name:     "a relative target resolves against the link's own directory",
			linkPath: "/a/b/link",
			linkname: "sibling.txt",
			want:     "/a/b/sibling.txt",
		},
		{
			name:     "a relative target may climb within the archive",
			linkPath: "/a/b/link",
			linkname: "../c/target.txt",
			want:     "/a/c/target.txt",
		},
		{
			name:     "a climb past the archive root is clamped at it",
			linkPath: "/a/b/link",
			linkname: "../../../../etc/passwd",
			want:     "/etc/passwd",
		},
		{
			name:     "an absolute target is archive-absolute, not host-absolute",
			linkPath: "/a/b/link",
			linkname: "/etc/passwd",
			want:     "/etc/passwd",
		},
		{
			name:     "a link at the archive root resolves against the root",
			linkPath: "/link",
			linkname: "target.txt",
			want:     "/target.txt",
		},
		{
			name:     "a target that is only a climb lands on the root itself",
			linkPath: "/a/link",
			linkname: "..",
			want:     "/",
		},
		{
			name:     "a hard link names its target from the archive root, not from its own directory",
			linkPath: "/opt/hard.jar",
			linkname: "opt/real.jar",
			hardLink: true,
			want:     "/opt/real.jar",
		},
		{
			name:     "a symlink with the same target text is relative to its own directory",
			linkPath: "/opt/sym.jar",
			linkname: "opt/real.jar",
			want:     "/opt/opt/real.jar",
		},
		{
			name:     "a hard link target is clamped at the root like any other",
			linkPath: "/opt/hard.jar",
			linkname: "../../etc/passwd",
			hardLink: true,
			want:     "/etc/passwd",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, resolveLinkWithinArchive(tt.linkPath, tt.linkname, tt.hardLink))
		})
	}
}
