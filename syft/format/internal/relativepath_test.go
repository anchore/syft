package internal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConvertAbsoluteToRelative(t *testing.T) {
	tests := []struct {
		name    string
		absPath string
		want    string
	}{
		{
			name:    "absolute path",
			absPath: "/usr/bin/foo",
			want:    "usr/bin/foo",
		},
		{
			name:    "relative path",
			absPath: "relative/path/bar",
			want:    "relative/path/bar",
		},
		{
			name:    "root path",
			absPath: "/",
			want:    "",
		},
		{
			name:    "dot relative path",
			absPath: "./foo",
			want:    "./foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ConvertAbsoluteToRelative(tt.absPath)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRel(t *testing.T) {
	tests := []struct {
		name   string
		base   string
		target string
		want   string
	}{
		{
			name:   "escaping symlink: target is sibling of base parent",
			base:   "/root/subdir",
			target: "/root/foo",
			want:   "../foo",
		},
		{
			name:   "target is child of base",
			base:   "/root/subdir",
			target: "/root/subdir/foo",
			want:   "foo",
		},
		{
			name:   "base equals target",
			base:   "/root",
			target: "/root",
			want:   ".",
		},
		{
			name:   "siblings under common parent",
			base:   "/root/a",
			target: "/root/b",
			want:   "../b",
		},
		{
			name:   "target is immediate child of root",
			base:   "/",
			target: "/foo",
			want:   "foo",
		},
		{
			name:   "deeper nesting",
			base:   "/a/b/c",
			target: "/a/d/e",
			want:   "../../d/e",
		},
		{
			name:   "target equals base with trailing content",
			base:   "/a/b",
			target: "/a/b/c/d",
			want:   "c/d",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Rel(tt.base, tt.target)
			assert.Equal(t, tt.want, got)
		})
	}
}
