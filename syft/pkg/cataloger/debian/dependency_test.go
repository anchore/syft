package debian

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
				Metadata: pkg.DpkgDBEntry{
					Provides: []string{"a-thing"},
					Depends:  []string{"b-thing"},
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
			name: "strip version specifiers + split package deps",
			p: pkg.Package{
				Name: "package-a",
				Metadata: pkg.DpkgDBEntry{
					Provides: []string{"foo [i386]"},
					Depends:  []string{"libgmp10 (>= 2:6.2.1+dfsg1)", "default-mta | mail-transport-agent"},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"package-a", "foo"},
					Requires: []string{"libgmp10", "default-mta", "mail-transport-agent"},
				},
			},
		},
		{
			name: "empty dependency data entries",
			p: pkg.Package{
				Name: "package-a",
				Metadata: pkg.DpkgDBEntry{
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
		name  string
		input string
		want  string
	}{
		{
			name:  "package name only",
			input: "test",
			want:  "test",
		},
		{
			name:  "with version",
			input: "test (1.2.3)",
			want:  "test",
		},
		{
			name:  "multiple packages",
			input: "test | other",
			want:  "test | other",
		},
		{
			name:  "with architecture specifiers",
			input: "test [amd64 i386]",
			want:  "test",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, stripVersionSpecifier(tt.input))
		})
	}
}
