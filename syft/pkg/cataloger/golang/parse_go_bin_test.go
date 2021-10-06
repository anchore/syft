package golang

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

func TestbuildGoPkgInfo(t *testing.T) {
	tests := []struct {
		name     string
		mod      string
		expected []pkg.Package
	}{
		{
			name:     "buildGoPkgInfo can parse a mod string and return packages",
			mod:      "",
			expected: make([]pkg.Package, 0),
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			pkgs := buildGoPkgInfo(tt.mod)
			assert.Equal(t, tt.expected, pkgs)
		})
	}
}
