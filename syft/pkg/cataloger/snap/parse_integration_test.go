package snap

import (
	"testing"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseSnapYaml(t *testing.T) {
	fixture := "test-fixtures/snap.yaml"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expected := []pkg.Package{
		{
			Name:      "test-snap",
			Version:   "1.0.0",
			Type:      pkg.DebPkg,
			PURL:      "pkg:generic/snap/test-snap@1.0.0?arch=amd64&base=core20&type=app",
			Locations: locations,
			Metadata: pkg.SnapEntry{
				SnapType:     pkg.SnapTypeApp,
				Base:         "core20",
				SnapName:     "test-snap",
				SnapVersion:  "1.0.0",
				Architecture: "amd64",
			},
		},
	}

	pkgtest.TestFileParser(t, fixture, parseSnapYaml, expected, nil)
}

func TestParseSystemManifest(t *testing.T) {
	fixture := "test-fixtures/manifest.yaml"
	locations := file.NewLocationSet(file.NewLocation(fixture))

	expected := []pkg.Package{
		{
			Name:      "grub-efi-amd64-signed",
			Version:   "1.202+2.12-1ubuntu7",
			Type:      pkg.DebPkg,
			PURL:      "pkg:deb/ubuntu/grub-efi-amd64-signed@1.202%2B2.12-1ubuntu7?arch=amd64", // URL encoded
			Locations: locations,
			Metadata: pkg.SnapEntry{
				SnapType:     pkg.SnapTypeApp, // Default type when gadget not detected from name
				Base:         "core24",
				SnapName:     "pc",
				SnapVersion:  "24-0.1",
				Architecture: "amd64", // From architectures array
			},
		},
		{
			Name:      "shim-signed",
			Version:   "1.56+15.7-0ubuntu1",
			Type:      pkg.DebPkg,
			PURL:      "pkg:deb/ubuntu/shim-signed@1.56%2B15.7-0ubuntu1?arch=amd64", // URL encoded
			Locations: locations,
			Metadata: pkg.SnapEntry{
				SnapType:     pkg.SnapTypeApp, // Default type when gadget not detected from name
				Base:         "core24",
				SnapName:     "pc",
				SnapVersion:  "24-0.1",
				Architecture: "amd64", // From architectures array
			},
		},
	}

	pkgtest.TestFileParser(t, fixture, parseSystemManifest, expected, nil)
}
