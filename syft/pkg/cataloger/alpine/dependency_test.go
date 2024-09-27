package alpine

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

func Test_dbEntryDependencySpecifier(t *testing.T) {
	tests := []struct {
		name string
		p    pkg.Package
		want dependency.Specification
	}{
		{
			name: "keeps given values + package name",
			p: pkg.Package{
				Name: "package-c",
				Metadata: pkg.ApkDBEntry{
					Provides:     []string{"a-thing"},
					Dependencies: []string{"b-thing"},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"package-c", "a-thing"},
					Requires: []string{"b-thing"},
				},
			},
		},
		{
			name: "strip version specifiers",
			p: pkg.Package{
				Name: "package-a",
				Metadata: pkg.ApkDBEntry{
					Provides:     []string{"so:libc.musl-x86_64.so.1=1"},
					Dependencies: []string{"so:libc.musl-x86_64.so.2=2"},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"package-a", "so:libc.musl-x86_64.so.1"},
					Requires: []string{"so:libc.musl-x86_64.so.2"},
				},
			},
		},
		{
			name: "empty dependency data entries",
			p: pkg.Package{
				Name: "package-a",
				Metadata: pkg.ApkDBEntry{
					Provides:     []string{""},
					Dependencies: []string{""},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"package-a"},
					Requires: nil,
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, dbEntryDependencySpecifier(tt.p))
		})
	}
}

func Test_stripVersionSpecifier(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "empty expression",
			version: "",
			want:    "",
		},
		{
			name:    "no expression",
			version: "cmd:foo",
			want:    "cmd:foo",
		},
		{
			name:    "=",
			version: "cmd:scanelf=1.3.4-r0",
			want:    "cmd:scanelf",
		},
		{
			name:    ">=",
			version: "cmd:scanelf>=1.3.4-r0",
			want:    "cmd:scanelf",
		},
		{
			name:    "<",
			version: "cmd:scanelf<1.3.4-r0",
			want:    "cmd:scanelf",
		},
		{
			name:    "ignores file paths",
			version: "/bin/sh",
			want:    "/bin/sh",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, stripVersionSpecifier(tt.version))
		})
	}
}
