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
		metadata elfBinaryPackageNotes
		want     string
	}{
		{
			name: "elf-binary-package-cataloger",
			metadata: elfBinaryPackageNotes{
				Name:    "github.com/anchore/syft",
				Version: "v0.1.0",
				ELFBinaryPackageNoteJSONPayload: pkg.ELFBinaryPackageNoteJSONPayload{
					System: "syftsys",
				},
			},
			want: "pkg:generic/syftsys/github.com/anchore/syft@v0.1.0",
		},
		{
			name: "elf binary package short name",
			metadata: elfBinaryPackageNotes{
				Name:    "go.opencensus.io",
				Version: "v0.23.0",
				ELFBinaryPackageNoteJSONPayload: pkg.ELFBinaryPackageNoteJSONPayload{
					System: "syftsys",
				},
			},
			want: "pkg:generic/syftsys/go.opencensus.io@v0.23.0",
		},
		{
			name: "no info",
			metadata: elfBinaryPackageNotes{
				Name:    "test",
				Version: "1.0",
				ELFBinaryPackageNoteJSONPayload: pkg.ELFBinaryPackageNoteJSONPayload{
					Type: "rpm",
				},
			},
			want: "pkg:rpm/test@1.0",
		},
		{
			name: "with system",
			metadata: elfBinaryPackageNotes{
				Name:    "test",
				Version: "1.0",
				ELFBinaryPackageNoteJSONPayload: pkg.ELFBinaryPackageNoteJSONPayload{
					Type:   "rpm",
					System: "system",
				},
			},
			want: "pkg:rpm/system/test@1.0",
		},
		{
			name: "with os info preferred",
			metadata: elfBinaryPackageNotes{
				Name:    "test",
				Version: "1.0",
				ELFBinaryPackageNoteJSONPayload: pkg.ELFBinaryPackageNoteJSONPayload{
					Type:      "rpm",
					OS:        "fedora",
					OSVersion: "2.0",
					OSCPE:     "cpe:/o:someone:redhat:3.0",
				},
			},
			want: "pkg:rpm/fedora/test@1.0?distro=fedora-2.0",
		},
		{
			name: "with os info fallback to CPE parsing (missing version)",
			metadata: elfBinaryPackageNotes{
				Name:    "test",
				Version: "1.0",
				ELFBinaryPackageNoteJSONPayload: pkg.ELFBinaryPackageNoteJSONPayload{
					Type:  "rpm",
					OS:    "fedora",
					OSCPE: "cpe:/o:someone:redhat:3.0",
				},
			},
			want: "pkg:rpm/redhat/test@1.0?distro=redhat-3.0",
		},
		{
			name: "with os info preferred (missing OS)",
			metadata: elfBinaryPackageNotes{
				Name:    "test",
				Version: "1.0",
				ELFBinaryPackageNoteJSONPayload: pkg.ELFBinaryPackageNoteJSONPayload{
					Type:      "rpm",
					OSVersion: "2.0",
					OSCPE:     "cpe:/o:someone:redhat:3.0",
				},
			},
			want: "pkg:rpm/redhat/test@1.0?distro=redhat-3.0",
		},
		{
			name: "missing type",
			metadata: elfBinaryPackageNotes{
				Name:    "test",
				Version: "1.0",
				ELFBinaryPackageNoteJSONPayload: pkg.ELFBinaryPackageNoteJSONPayload{
					System: "system",
				},
			},
			want: "pkg:generic/system/test@1.0",
		},
		{
			name: "bad or missing OSCPE data cannot be parsed allows for correct string",
			metadata: elfBinaryPackageNotes{
				Name:    "test",
				Version: "1.0",
				ELFBinaryPackageNoteJSONPayload: pkg.ELFBinaryPackageNoteJSONPayload{
					System: "system",
					OSCPE:  "%$#*(#*@&$(",
				},
			},
			want: "pkg:generic/system/test@1.0",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, packageURL(test.metadata))
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
				ELFBinaryPackageNoteJSONPayload: pkg.ELFBinaryPackageNoteJSONPayload{
					Type:   "binary",
					System: "syftsys",
				},
			},

			expected: pkg.Package{
				Name:    "syfttestfixture",
				Version: "0.01",
				Type:    "binary",
				PURL:    "pkg:generic/syftsys/syfttestfixture@0.01",
				Metadata: pkg.ELFBinaryPackageNoteJSONPayload{
					Type:   "binary",
					System: "syftsys",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := newELFPackage(test.metadata, file.NewLocationSet())
			if diff := cmp.Diff(test.expected, actual, cmpopts.IgnoreFields(pkg.Package{}, "id"), cmpopts.IgnoreUnexported(pkg.Package{}, file.LocationSet{}, pkg.LicenseSet{})); diff != "" {
				t.Errorf("newELFPackage() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
