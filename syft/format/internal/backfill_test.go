package internal

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

func Test_Backfill(t *testing.T) {
	tests := []struct {
		name     string
		in       pkg.Package
		expected pkg.Package
	}{
		{
			name: "npm type",
			in: pkg.Package{
				PURL: "pkg:npm/test@3.0.0",
			},
			expected: pkg.Package{
				PURL:     "pkg:npm/test@3.0.0",
				Type:     pkg.NpmPkg,
				Language: pkg.JavaScript,
				Name:     "test",
				Version:  "3.0.0",
			},
		},
		{
			name: "rpm no epoch",
			in: pkg.Package{
				PURL: "pkg:rpm/redhat/dbus-common@1.12.8-26.el8?arch=noarch&distro=rhel-8.10&upstream=dbus-1.12.8-26.el8.src.rpm",
			},
			expected: pkg.Package{
				PURL:    "pkg:rpm/redhat/dbus-common@1.12.8-26.el8?arch=noarch&distro=rhel-8.10&upstream=dbus-1.12.8-26.el8.src.rpm",
				Type:    pkg.RpmPkg,
				Name:    "dbus-common",
				Version: "1.12.8-26.el8",
			},
		},
		{
			name: "rpm epoch",
			in: pkg.Package{
				PURL: "pkg:rpm/redhat/dbus-common@1.12.8-26.el8?arch=noarch&distro=rhel-8.10&epoch=1&upstream=dbus-1.12.8-26.el8.src.rpm",
			},
			expected: pkg.Package{
				PURL:    "pkg:rpm/redhat/dbus-common@1.12.8-26.el8?arch=noarch&distro=rhel-8.10&epoch=1&upstream=dbus-1.12.8-26.el8.src.rpm",
				Type:    pkg.RpmPkg,
				Name:    "dbus-common",
				Version: "1:1.12.8-26.el8",
			},
		},
		{
			name: "bad cpe",
			in: pkg.Package{
				PURL: "pkg:npm/testp@3.0.0?cpes=cpe:2.3a:testv:testp:3.0.0:*:*:*:*:*:*:*",
			},
			expected: pkg.Package{
				PURL:     "pkg:npm/testp@3.0.0?cpes=cpe:2.3a:testv:testp:3.0.0:*:*:*:*:*:*:*",
				Type:     pkg.NpmPkg,
				Language: pkg.JavaScript,
				Name:     "testp",
				Version:  "3.0.0",
			},
		},
		{
			name: "good cpe",
			in: pkg.Package{
				PURL: "pkg:npm/testp@3.0.0?cpes=cpe:2.3:a:testv:testp:3.0.0:*:*:*:*:*:*:*",
			},
			expected: pkg.Package{
				PURL:     "pkg:npm/testp@3.0.0?cpes=cpe:2.3:a:testv:testp:3.0.0:*:*:*:*:*:*:*",
				Type:     pkg.NpmPkg,
				Language: pkg.JavaScript,
				Name:     "testp",
				Version:  "3.0.0",
				CPEs: []cpe.CPE{
					{
						Attributes: cpe.Attributes{
							Part:    "a",
							Vendor:  "testv",
							Product: "testp",
							Version: "3.0.0",
						},
						Source: cpe.DeclaredSource,
					},
				},
			},
		},
		{
			name: "java type",
			in: pkg.Package{
				PURL: "pkg:maven/org.apache/some-thing@1.2.3",
			},
			expected: pkg.Package{
				PURL:     "pkg:maven/org.apache/some-thing@1.2.3",
				Type:     pkg.JavaPkg,
				Language: pkg.Java,
				Name:     "some-thing",
				Version:  "1.2.3",
				// we intentionally don't claim we found a pom properties file with a groupID from the purl.
				// but we do claim that we found java data with an empty type.
				Metadata: pkg.JavaArchive{},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			Backfill(&tt.in)
			tt.in.OverrideID("")
			require.Equal(t, tt.expected, tt.in)
		})
	}
}

func Test_nameFromPurl(t *testing.T) {
	tests := []struct {
		in       string
		expected string
	}{
		{
			in:       "pkg:npm/some-name@3.0.0",
			expected: "some-name",
		},
		{
			in:       "pkg:maven/org.apache/some-name@1.2.3",
			expected: "some-name",
		},
		{
			in:       "pkg:deb/debian/some-name@3.0.0",
			expected: "some-name",
		},
		{
			in:       "pkg:rpm/redhat/some-name@3.0.0",
			expected: "some-name",
		},
		{
			in:       "pkg:gem/some-name@3.0.0",
			expected: "some-name",
		},
		{
			in:       "pkg:apk/alpine/some-name@3.0.0",
			expected: "some-name",
		},
		{
			in:       "pkg:docker/some-org/some-name@3.0.0",
			expected: "some-org/some-name",
		},
		{
			in:       "pkg:npm/some-name@3.0.0",
			expected: "some-name",
		},
		{
			in:       "pkg:npm/some-org/some-name@3.0.0",
			expected: "some-org/some-name",
		},
		{
			in:       "pkg:oci/library/mysql@8.1.0",
			expected: "library/mysql",
		},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			p, err := packageurl.FromString(tt.in)
			require.NoError(t, err)
			got := nameFromPurl(p)
			require.Equal(t, tt.expected, got)
		})
	}
}
