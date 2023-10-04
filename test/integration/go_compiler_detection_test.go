package integration

import (
	"testing"

	"github.com/anchore/syft/syft/source"
)

func TestGolangCompilerDetection(t *testing.T) {
	tests := []struct {
		name              string
		image             string
		expectedCompilers []string
	}{
		{
			name:              "syft can detect a single golang compiler given the golang base image",
			image:             "image-golang-compiler",
			expectedCompilers: []string{"1.18.10"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom, _ := catalogFixtureImage(t, tt.image, source.SquashedScope, nil)
			packages := sbom.Artifacts.Packages.PackagesByName("Golang Standard Library")
			foundCompilerVersions := make(map[string]struct{})
			for _, pkg := range packages {
				foundCompilerVersions[pkg.Version] = struct{}{}
			}
			for _, expectedCompiler := range tt.expectedCompilers {
				if _, ok := foundCompilerVersions[expectedCompiler]; !ok {
					t.Fatalf("expected %s version not found in found compilers: %v", expectedCompiler, foundCompilerVersions)
				}
			}
		})
	}
}
