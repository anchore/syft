package binary

import (
	"testing"

	"github.com/stretchr/testify/require"

	extFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_ELFPackageCataloger(t *testing.T) {

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
		{
			name:    "Debian 64 bit binaries w/o os version",
			fixture: "image-wolfi-64bit-without-version",
			expected: []pkg.Package{
				{
					Name:    "glibc",
					Version: "2.42-r4",
					PURL:    "pkg:apk/wolfi/glibc@2.42-r4?distro=wolfi",
					Locations: file.NewLocationSet(
						file.NewLocationFromDirectory("/lib/libBrokenLocale.so.1",
							"sha256:559eaef4e501b8e7a150661a94ee8b9ebc63bfca3256953a703f9f82053346f2",
							*extFile.NewFileReference("/lib/libBrokenLocale.so.1")).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
					),
					Licenses: pkg.NewLicenseSet(),
					Type:     pkg.ApkPkg,
					Metadata: pkg.ELFBinaryPackageNoteJSONPayload{
						Type:         "apk",
						Architecture: "x86_64",
						OS:           "wolfi",
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

func Test_unmarshalELFPackageNotesPayload(t *testing.T) {
	tests := []struct {
		name        string
		payload     string
		wantOSCPE   string
		wantCorrect string
		wantErr     require.ErrorAssertionFunc
	}{
		{
			name:        "only osCPE (incorrect) provided",
			payload:     `{"name":"test","version":"1.0","osCPE":"cpe:/o:fedoraproject:fedora:40"}`,
			wantOSCPE:   "cpe:/o:fedoraproject:fedora:40",
			wantCorrect: "",
		},
		{
			name:        "only osCpe (correct) provided",
			payload:     `{"name":"test","version":"1.0","osCpe":"cpe:/o:fedoraproject:fedora:40"}`,
			wantOSCPE:   "cpe:/o:fedoraproject:fedora:40",
			wantCorrect: "cpe:/o:fedoraproject:fedora:40",
		},
		{
			name:        "both osCPE and osCpe provided uses osCPE",
			payload:     `{"name":"test","version":"1.0","osCPE":"cpe:/o:fedoraproject:fedora:40","osCpe":"cpe:/o:redhat:rhel:9"}`,
			wantOSCPE:   "cpe:/o:fedoraproject:fedora:40",
			wantCorrect: "cpe:/o:redhat:rhel:9",
		},
		{
			name:        "neither osCPE nor osCpe provided",
			payload:     `{"name":"test","version":"1.0"}`,
			wantOSCPE:   "",
			wantCorrect: "",
		},
		{
			name:    "invalid JSON",
			payload: `{invalid}`,
			wantErr: require.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = require.NoError
			}

			got, err := unmarshalELFPackageNotesPayload([]byte(tt.payload))
			tt.wantErr(t, err)

			if err != nil {
				return
			}

			require.Equal(t, tt.wantOSCPE, got.OSCPE)
			require.Equal(t, tt.wantCorrect, got.CorrectOSCPE)
		})
	}
}
