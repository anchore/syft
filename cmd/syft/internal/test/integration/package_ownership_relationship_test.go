package integration

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/format/syftjson"
	syftjsonModel "github.com/anchore/syft/syft/format/syftjson/model"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestPackageOwnershipRelationships(t *testing.T) {
	// ensure that the json encoder is applying artifact ownership with an image that has expected ownership relationships
	tests := []struct {
		fixture string
	}{
		{
			fixture: "image-owning-package",
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			sbom, _ := catalogFixtureImage(t, test.fixture, source.SquashedScope)

			output := bytes.NewBufferString("")
			err := syftjson.NewFormatEncoder().Encode(output, sbom)
			require.NoError(t, err)

			var doc syftjsonModel.Document
			decoder := json.NewDecoder(output)
			if err := decoder.Decode(&doc); err != nil {
				t.Fatalf("unable to decode json doc: %+v", err)
			}

			if len(doc.ArtifactRelationships) == 0 {
				t.Errorf("expected to find relationships between packages but found none")
			}

		})
	}

}

func TestPackageOwnershipExclusions(t *testing.T) {
	// ensure that the json encoder is excluding packages by artifact ownership with an image that has expected ownership relationships
	tests := []struct {
		name    string
		fixture string
	}{
		{
			name:    "busybox binary is filtered based on ownership relationship",
			fixture: "image-os-binary-overlap",
		},
	}

	for _, test := range tests {
		t.Run(test.fixture, func(t *testing.T) {
			sbom, _ := catalogFixtureImage(t, test.fixture, source.SquashedScope)
			binaryPackages := make([]pkg.Package, 0)
			apkPackages := make([]pkg.Package, 0)
			for p := range sbom.Artifacts.Packages.Enumerate() {
				if p.Type == pkg.BinaryPkg && p.Name == "busybox" {
					binaryPackages = append(binaryPackages, p)
				}
				if p.Type == pkg.ApkPkg && p.Name == "busybox" {
					apkPackages = append(apkPackages, p)
				}
			}

			if len(binaryPackages) != 0 {
				packageNames := make([]string, 0)
				for _, p := range binaryPackages {
					packageNames = append(packageNames, p.Name)
				}
				t.Errorf("expected to find no binary packages but found %d packages: %v", len(binaryPackages), packageNames)
			}
			if len(apkPackages) == 0 {
				t.Errorf("expected to find apk packages but found none")
			}
		})
	}
}
