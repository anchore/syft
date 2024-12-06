package arch

import (
	"testing"

	"github.com/sergi/go-diff/diffmatchpatch"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
)

func Test_PackageURL(t *testing.T) {
	tests := []struct {
		name     string
		metadata *parsedData
		distro   linux.Release
		expected string
	}{
		{
			name: "bad distro id",
			metadata: &parsedData{
				Licenses: "",
				AlpmDBEntry: pkg.AlpmDBEntry{
					Package:      "p",
					Version:      "v",
					Architecture: "a",
				},
			},
			distro: linux.Release{
				ID:      "something-else",
				BuildID: "rolling",
			},
			expected: "",
		},
		{
			name: "gocase",
			metadata: &parsedData{
				Licenses: "",
				AlpmDBEntry: pkg.AlpmDBEntry{
					Package:      "p",
					Version:      "v",
					Architecture: "a",
				},
			},
			distro: linux.Release{
				ID:      "arch",
				BuildID: "rolling",
			},
			expected: "pkg:alpm/arch/p@v?arch=a&distro=arch-rolling",
		},
		{
			name: "missing architecture",
			metadata: &parsedData{
				Licenses: "",
				AlpmDBEntry: pkg.AlpmDBEntry{
					Package: "p",
					Version: "v",
				},
			},
			distro: linux.Release{
				ID: "arch",
			},
			expected: "pkg:alpm/arch/p@v?distro=arch",
		},
		{
			metadata: &parsedData{
				Licenses: "",
				AlpmDBEntry: pkg.AlpmDBEntry{
					Package:      "python",
					Version:      "3.10.0",
					Architecture: "any",
				},
			},
			distro: linux.Release{
				ID:      "arch",
				BuildID: "rolling",
			},
			expected: "pkg:alpm/arch/python@3.10.0?arch=any&distro=arch-rolling",
		},
		{
			metadata: &parsedData{
				Licenses: "",
				AlpmDBEntry: pkg.AlpmDBEntry{
					Package:      "g plus plus",
					Version:      "v84",
					Architecture: "x86_64",
				},
			},
			distro: linux.Release{
				ID:      "arch",
				BuildID: "rolling",
			},
			expected: "pkg:alpm/arch/g%20plus%20plus@v84?arch=x86_64&distro=arch-rolling",
		},
		{
			name: "add source information as qualifier",
			metadata: &parsedData{
				Licenses: "",
				AlpmDBEntry: pkg.AlpmDBEntry{
					Package:      "p",
					Version:      "v",
					Architecture: "a",
					BasePackage:  "origin",
				},
			},
			distro: linux.Release{
				ID:      "arch",
				BuildID: "rolling",
			},
			expected: "pkg:alpm/arch/p@v?arch=a&distro=arch-rolling&upstream=origin",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := packageURL(test.metadata, &test.distro)
			if actual != test.expected {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.expected, actual, true)
				t.Errorf("diff: %s", dmp.DiffPrettyText(diffs))
			}

			if test.expected == "" {
				return
			}

			// verify packageurl can parse
			purl, err := packageurl.FromString(actual)
			if err != nil {
				t.Errorf("cannot re-parse purl: %s", actual)
			}
			if purl.Name != test.metadata.Package {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.metadata.Package, purl.Name, true)
				t.Errorf("invalid purl name: %s", dmp.DiffPrettyText(diffs))
			}
			if purl.Version != test.metadata.Version {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.metadata.Version, purl.Version, true)
				t.Errorf("invalid purl version: %s", dmp.DiffPrettyText(diffs))
			}
			if purl.Qualifiers.Map()["arch"] != test.metadata.Architecture {
				dmp := diffmatchpatch.New()
				diffs := dmp.DiffMain(test.metadata.Architecture, purl.Qualifiers.Map()["arch"], true)
				t.Errorf("invalid purl architecture: %s", dmp.DiffPrettyText(diffs))
			}
		})
	}
}
