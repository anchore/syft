package elixir

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

func Test_extractMixLockDependencies(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []string
	}{
		{
			name: "no dependencies",
			line: `  "castore": {:hex, :castore, "0.1.17", "hash", [:mix], [], "hexpm", "ext"},`,
			want: nil,
		},
		{
			name: "single dependency",
			line: `  "esbuild": {:hex, :esbuild, "0.5.0", "hash", [:mix], [{:castore, ">= 0.0.0", [hex: :castore, repo: "hexpm", optional: false]}], "hexpm", "ext"},`,
			want: []string{"castore"},
		},
		{
			name: "multiple dependencies",
			line: `  "cowboy": {:hex, :cowboy, "2.9.0", "hash", [:make, :rebar3], [{:cowlib, "2.11.0", [hex: :cowlib]}, {:ranch, "1.8.0", [hex: :ranch]}], "hexpm", "ext"},`,
			want: []string{"cowlib", "ranch"},
		},
		{
			name: "git source is skipped like hex source",
			line: `  "mydep": {:git, "https://github.com/example/mydep.git", "ref", [{:jason, "~> 1.0", [hex: :jason]}]},`,
			want: []string{"jason"},
		},
		{
			name: "not a package line",
			line: `%{`,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractMixLockDependencies(tt.line))
		})
	}
}

func Test_mixLockDependencySpecifier(t *testing.T) {
	tests := []struct {
		name string
		p    pkg.Package
		want dependency.Specification
	}{
		{
			name: "provides its name and requires its dependencies",
			p: pkg.Package{
				Name: "cowboy",
				Metadata: pkg.ElixirMixLockEntry{
					Name:         "cowboy",
					Dependencies: []string{"cowlib", "ranch"},
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"cowboy"},
					Requires: []string{"cowlib", "ranch"},
				},
			},
		},
		{
			name: "no dependencies still provides its name",
			p: pkg.Package{
				Name: "castore",
				Metadata: pkg.ElixirMixLockEntry{
					Name: "castore",
				},
			},
			want: dependency.Specification{
				ProvidesRequires: dependency.ProvidesRequires{
					Provides: []string{"castore"},
				},
			},
		},
		{
			name: "wrong metadata type yields empty specification",
			p: pkg.Package{
				Name:     "mystery",
				Metadata: pkg.RubyGemspec{},
			},
			want: dependency.Specification{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, mixLockDependencySpecifier(tt.p))
		})
	}
}
