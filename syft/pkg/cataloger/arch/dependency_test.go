package arch

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
				Metadata: pkg.AlpmDBEntry{
					Provides: []string{"a-thing"},
					Depends:  []string{"b-thing"},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"package-c", "a-thing", "a-thing"}, //  note: gets deduplicated downstream
					Requires: []string{"b-thing"},
				},
			},
		},
		{
			name: "strip version specifiers",
			p: pkg.Package{
				Name: "package-a",
				Metadata: pkg.AlpmDBEntry{
					Provides: []string{"libtree-sitter.so.me=1-64"},
					Depends:  []string{"libtree-sitter.so.thing=2-64"},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"package-a", "libtree-sitter.so.me=1-64", "libtree-sitter.so.me"},
					Requires: []string{"libtree-sitter.so.thing=2-64"},
				},
			},
		},
		{
			name: "empty dependency data entries",
			p: pkg.Package{
				Name: "package-a",
				Metadata: pkg.AlpmDBEntry{
					Provides: []string{""},
					Depends:  []string{""},
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
			version: "gcc-libs",
			want:    "gcc-libs",
		},
		{
			name:    "=",
			version: "libtree-sitter.so=0-64",
			want:    "libtree-sitter.so",
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
