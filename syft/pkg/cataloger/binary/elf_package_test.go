package binary

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_packageURL(t *testing.T) {
	tests := []struct {
		name     string
		notes    elfBinaryPackageNotes
		expected string
	}{
		{
			name: "elf-binary-package-cataloger",
			notes: elfBinaryPackageNotes{
				Name:    "github.com/anchore/syft",
				Version: "v0.1.0",
				ELFBinaryPackageNotes: pkg.ELFBinaryPackageNotes{
					System: "syftsys",
				},
			},
			expected: "pkg:generic/syftsys/github.com/anchore/syft@v0.1.0",
		},
		{
			name: "elf binary package short name",
			notes: elfBinaryPackageNotes{
				Name:    "go.opencensus.io",
				Version: "v0.23.0",
				ELFBinaryPackageNotes: pkg.ELFBinaryPackageNotes{
					System: "syftsys",
				},
			},
			expected: "pkg:generic/syftsys/go.opencensus.io@v0.23.0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, packageURL(test.notes))
		})
	}
}

func Test_newELFPackage(t *testing.T) {
	tests := []struct {
		name     string
		metadata elfBinaryPackageNotes
		expected pkg.Package
	}{
		{
			name: "elf-binary-package-cataloger",
			metadata: elfBinaryPackageNotes{
				Name:    "syfttestfixture",
				Version: "0.01",
				PURL:    "pkg:generic/syftsys/syfttestfixture@0.01",
				CPE:     "cpe:/o:syft:syftsys_testfixture_syfttestfixture:0.01",
				ELFBinaryPackageNotes: pkg.ELFBinaryPackageNotes{
					Type:   "binary",
					System: "syftsys",
				},
			},

			expected: pkg.Package{
				Name:    "syfttestfixture",
				Version: "0.01",
				Type:    "binary",
				PURL:    "pkg:generic/syftsys/syfttestfixture@0.01",
				Metadata: pkg.ELFBinaryPackageNotes{
					Type:   "binary",
					System: "syftsys",
				},
			},
		},
	}

	// for _, test := range tests {
	// 	t.Run(test.name, func(t *testing.T) {
	// 		assert.Equal(t, test.expected, newELFPackage(test.metadata, file.NewLocationSet(), nil))
	// 	})
	// }
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := newELFPackage(test.metadata, file.NewLocationSet(), nil)
			if diff := cmp.Diff(test.expected, actual, cmpopts.IgnoreFields(pkg.Package{}, "id"), cmpopts.IgnoreUnexported(pkg.Package{}, file.LocationSet{}, pkg.LicenseSet{})); diff != "" {
				t.Errorf("newELFPackage() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
