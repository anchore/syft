package integration

import (
	"testing"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/source"
)

func TestGolangCompilerDetection(t *testing.T) {
	tests := []struct {
		name              string
		image             string
		expectedCompilers []string
		expectedCPE       []cpe.CPE
		expectedPURL      []string
	}{
		{
			name:              "syft can detect a single golang compiler given the golang base image",
			image:             "image-golang-compiler",
			expectedCompilers: []string{"go1.18.10"},
			expectedCPE:       []cpe.CPE{cpe.Must("cpe:2.3:a:golang:go:1.18.10:-:*:*:*:*:*:*", cpe.GeneratedSource)},
			expectedPURL:      []string{"pkg:golang/stdlib@1.18.10"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sbom, _ := catalogFixtureImage(t, tt.image, source.SquashedScope)
			packages := sbom.Artifacts.Packages.PackagesByName("stdlib")

			foundCompilerVersions := make(map[string]struct{})
			foundCPE := make(map[cpe.CPE]struct{})
			foundPURL := make(map[string]struct{})

			for _, pkg := range packages {
				foundCompilerVersions[pkg.Version] = struct{}{}
				foundPURL[pkg.PURL] = struct{}{}
				for _, c := range pkg.CPEs {
					foundCPE[c] = struct{}{}
				}
			}

			for _, expectedCompiler := range tt.expectedCompilers {
				if _, ok := foundCompilerVersions[expectedCompiler]; !ok {
					t.Fatalf("expected %s version; not found in found compilers: %v", expectedCompiler, foundCompilerVersions)
				}
			}

			for _, expectedPURL := range tt.expectedPURL {
				if _, ok := foundPURL[expectedPURL]; !ok {
					t.Fatalf("expected %s purl; not found in found purl: %v", expectedPURL, expectedPURLs)
				}
			}

			for _, expectedCPE := range tt.expectedCPE {
				if _, ok := foundCPE[expectedCPE]; !ok {
					t.Fatalf("expected %s version; not found in found cpe: %v", expectedCPE, expectedCPE)
				}
			}
		})
	}
}
