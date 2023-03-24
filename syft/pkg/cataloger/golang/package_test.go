package golang

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/pkg"
)

func Test_packageURL(t *testing.T) {

	tests := []struct {
		name     string
		pkg      pkg.Package
		expected string
	}{
		{
			name: "gocase",
			pkg: pkg.Package{
				Name:    "github.com/anchore/syft",
				Version: "v0.1.0",
			},
			expected: "pkg:golang/github.com/anchore/syft@v0.1.0",
		},
		{
			name: "golang short name",
			pkg: pkg.Package{
				Name:    "go.opencensus.io",
				Version: "v0.23.0",
			},
			expected: "pkg:golang/go.opencensus.io@v0.23.0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, packageURL(test.pkg.Name, test.pkg.Version))
		})
	}
}
