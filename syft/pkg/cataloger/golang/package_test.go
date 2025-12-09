package golang

import (
	"runtime/debug"
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
		{
			name: "golang with subpath",
			pkg: pkg.Package{
				Name:    "github.com/coreos/go-systemd/v22",
				Version: "v22.1.0",
			},
			expected: "pkg:golang/github.com/coreos/go-systemd@v22.1.0#v22",
		},
		{
			name: "golang with subpath deep",
			pkg: pkg.Package{
				Name: "google.golang.org/genproto/googleapis/api/annotations",
			},
			expected: "pkg:golang/google.golang.org/genproto/googleapis#api/annotations",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, packageURL(test.pkg.Name, test.pkg.Version))
		})
	}
}

func Test_newGoBinaryPackage_relativeReplace(t *testing.T) {
	tests := []struct {
		name         string
		dep          *debug.Module
		expectedName string
	}{
		{
			name: "relative replace with ../",
			dep: &debug.Module{
				Path:    "github.com/aws/aws-sdk-go-v2",
				Version: "(devel)",
				Replace: &debug.Module{
					Path:    "../../",
					Version: "(devel)",
				},
			},
			expectedName: "github.com/aws/aws-sdk-go-v2", // should use original path, not relative
		},
		{
			name: "relative replace with ./",
			dep: &debug.Module{
				Path:    "github.com/example/module",
				Version: "v1.0.0",
				Replace: &debug.Module{
					Path:    "./local",
					Version: "v0.0.0",
				},
			},
			expectedName: "github.com/example/module", // should use original path
		},
		{
			name: "absolute replace",
			dep: &debug.Module{
				Path:    "github.com/old/module",
				Version: "v1.0.0",
				Replace: &debug.Module{
					Path:    "github.com/new/module",
					Version: "v2.0.0",
				},
			},
			expectedName: "github.com/new/module", // should use replacement path
		},
		{
			name: "no replace",
			dep: &debug.Module{
				Path:    "github.com/normal/module",
				Version: "v1.0.0",
			},
			expectedName: "github.com/normal/module", // should use original path
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cataloger := &goBinaryCataloger{}
			result := cataloger.newGoBinaryPackage(test.dep, pkg.GolangBinaryBuildinfoEntry{}, nil)

			assert.Equal(t, test.expectedName, result.Name)
			assert.Equal(t, pkg.Go, result.Language)
			assert.Equal(t, pkg.GoModulePkg, result.Type)
		})
	}
}
