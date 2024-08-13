package binary

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_ELF_Package_Cataloger(t *testing.T) {

	cases := []struct {
		name     string
		fixture  string
		expected []pkg.Package
		wantErr  require.ErrorAssertionFunc
	}{
		{
			name:    "go case",
			fixture: "elf-test-fixtures",
			expected: []pkg.Package{
				{
					Name:    "libhello_world.so",
					Version: "0.01",
					PURL:    "pkg:generic/syftsys/libhello_world.so@0.01",
					Locations: file.NewLocationSet(
						file.NewVirtualLocation("/usr/local/bin/elftests/elfbinwithnestedlib/bin/lib/libhello_world.so", "/usr/local/bin/elftests/elfbinwithnestedlib/bin/lib/libhello_world.so"),
						file.NewVirtualLocation("/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world.so", "/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world.so"),
						file.NewVirtualLocation("/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world2.so", "/usr/local/bin/elftests/elfbinwithsisterlib/lib/libhello_world2.so"),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.License{Value: "MIT", SPDXExpression: "MIT", Type: "declared"},
					),

					Type: pkg.BinaryPkg,
					Metadata: pkg.ELFBinaryPackageNoteJSONPayload{
						Type:       "testfixture",
						Vendor:     "syft",
						System:     "syftsys",
						SourceRepo: "https://github.com/someone/somewhere.git",
						Commit:     "5534c38d0ffef9a3f83154f0b7a7fb6ab0ab6dbb",
					},
				},
				{
					Name:    "syfttestfixture",
					Version: "0.01",
					PURL:    "pkg:generic/syftsys/syfttestfixture@0.01",
					Locations: file.NewLocationSet(
						file.NewLocation("/usr/local/bin/elftests/elfbinwithnestedlib/bin/elfbinwithnestedlib").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
						file.NewLocation("/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin1").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
						file.NewLocation("/usr/local/bin/elftests/elfbinwithsisterlib/bin/elfwithparallellibbin2").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					Licenses: pkg.NewLicenseSet(
						pkg.License{Value: "MIT", SPDXExpression: "MIT", Type: "declared"},
					),
					Type: pkg.BinaryPkg,
					Metadata: pkg.ELFBinaryPackageNoteJSONPayload{
						Type:       "testfixture",
						Vendor:     "syft",
						System:     "syftsys",
						SourceRepo: "https://github.com/someone/somewhere.git",
						Commit:     "5534c38d0ffef9a3f83154f0b7a7fb6ab0ab6dbb",
					},
				},
			},
			wantErr: require.Error,
		},
		{
			name:    "fedora 64 bit binaries",
			fixture: "image-fedora-64bit",
			expected: []pkg.Package{
				{
					Name:    "coreutils",
					Version: "9.5-3.fc41",
					PURL:    "pkg:rpm/fedora/coreutils@9.5-3.fc41?distro=fedora-40",
					Locations: file.NewLocationSet(
						file.NewLocation("/sha256sum").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
						file.NewLocation("/sha1sum").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					Licenses: pkg.NewLicenseSet(),
					Type:     pkg.RpmPkg,
					Metadata: pkg.ELFBinaryPackageNoteJSONPayload{
						Type:         "rpm",
						Architecture: "x86_64",
						OSCPE:        "cpe:/o:fedoraproject:fedora:40",
					},
				},
			},
		},
		{
			name:    "fedora 32 bit binaries",
			fixture: "image-fedora-32bit",
			expected: []pkg.Package{
				{
					Name:    "coreutils",
					Version: "9.0-5.fc36",
					PURL:    "pkg:rpm/fedora/coreutils@9.0-5.fc36?distro=fedora-36",
					Locations: file.NewLocationSet(
						file.NewLocation("/sha256sum").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
						file.NewLocation("/sha1sum").WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					Licenses: pkg.NewLicenseSet(),
					Type:     pkg.RpmPkg,
					Metadata: pkg.ELFBinaryPackageNoteJSONPayload{
						Type:         "rpm",
						Architecture: "arm",
						OSCPE:        "cpe:/o:fedoraproject:fedora:36",
					},
				},
			},
		},
	}

	for _, v := range cases {
		t.Run(v.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				WithImageResolver(t, v.fixture).
				IgnoreLocationLayer(). // this fixture can be rebuilt, thus the layer ID will change
				Expects(v.expected, nil).
				WithErrorAssertion(v.wantErr).
				TestCataloger(t, NewELFPackageCataloger())
		})
	}

}
