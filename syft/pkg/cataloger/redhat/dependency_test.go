package redhat

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
				Metadata: pkg.RpmDBEntry{
					Provides: []string{"a-thing"},
					Requires: []string{"b-thing"},
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
			name: "strip unsupported keys",
			p: pkg.Package{
				Name: "package-a",
				Metadata: pkg.RpmDBEntry{
					Provides: []string{"libc.so.6(GLIBC_2.11)(64bit)"},
					Requires: []string{"config(bash)", "(llvm if clang)"},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"package-a", "libc.so.6(GLIBC_2.11)(64bit)"},
					Requires: []string{"config(bash)"},
				},
			},
		},
		{
			name: "empty dependency data entries",
			p: pkg.Package{
				Name: "package-a",
				Metadata: pkg.RpmDBEntry{
					Provides: []string{""},
					Requires: []string{""},
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

func Test_isSupportedKey(t *testing.T) {

	tests := []struct {
		name string
		key  string
		want bool
	}{
		{
			name: "paths allowed",
			key:  "/usr/bin/sh",
			want: true,
		},
		{
			name: "spaces stripped",
			key:  " filesystem ",
			want: true,
		},
		{
			name: "empty key",
			key:  "",
			want: true,
		},
		{
			name: "boolean expression",
			key:  "(pyproject-rpm-macros = 1.9.0-1.el9 if pyproject-rpm-macros)",
			want: false,
		},
		{
			name: "boolean expression with spaces stripped",
			key:  " (llvm if clang)",
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isSupportedKey(tt.key))
		})
	}
}
