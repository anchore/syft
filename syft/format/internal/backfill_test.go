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
				Metadata: pkg.RpmDBEntry{
					Arch: "noarch",
				},
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
				Metadata: pkg.RpmDBEntry{
					Arch: "noarch",
				},
			},
		},
		{
			name: "rpm with rpmmod",
			in: pkg.Package{
				PURL: "pkg:rpm/redhat/httpd@2.4.37-51?arch=x86_64&distro=rhel-8.7&rpmmod=httpd:2.4",
			},
			expected: pkg.Package{
				PURL:    "pkg:rpm/redhat/httpd@2.4.37-51?arch=x86_64&distro=rhel-8.7&rpmmod=httpd:2.4",
				Type:    pkg.RpmPkg,
				Name:    "httpd",
				Version: "2.4.37-51",
				Metadata: pkg.RpmDBEntry{
					ModularityLabel: strRef("httpd:2.4"),
					Arch:            "x86_64",
				},
			},
		},
		{
			name: "rpm with arch and no rpmmod",
			in: pkg.Package{
				PURL: "pkg:rpm/redhat/httpd@2.4.37-51?arch=x86_64&distro=rhel-8.7",
			},
			expected: pkg.Package{
				PURL:    "pkg:rpm/redhat/httpd@2.4.37-51?arch=x86_64&distro=rhel-8.7",
				Type:    pkg.RpmPkg,
				Name:    "httpd",
				Version: "2.4.37-51",
				Metadata: pkg.RpmDBEntry{
					Arch: "x86_64",
				},
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
		// deb cases
		{
			name: "deb nil metadata gets arch set",
			in: pkg.Package{
				PURL: "pkg:deb/debian/curl@7.74.0-1.3+deb11u7?arch=amd64&distro=debian-11",
			},
			expected: pkg.Package{
				PURL:    "pkg:deb/debian/curl@7.74.0-1.3+deb11u7?arch=amd64&distro=debian-11",
				Type:    pkg.DebPkg,
				Name:    "curl",
				Version: "7.74.0-1.3+deb11u7",
				Metadata: pkg.DpkgDBEntry{
					Architecture: "amd64",
				},
			},
		},
		{
			name: "deb arch:all preserved (nil metadata)",
			in: pkg.Package{
				PURL: "pkg:deb/debian/tzdata@2021a-1+deb11u10?arch=all&distro=debian-11",
			},
			expected: pkg.Package{
				PURL:    "pkg:deb/debian/tzdata@2021a-1+deb11u10?arch=all&distro=debian-11",
				Type:    pkg.DebPkg,
				Name:    "tzdata",
				Version: "2021a-1+deb11u10",
				Metadata: pkg.DpkgDBEntry{
					Architecture: "all",
				},
			},
		},
		{
			name: "deb populated metadata empty arch gets filled",
			in: pkg.Package{
				PURL: "pkg:deb/debian/curl@7.74.0-1.3+deb11u7?arch=amd64&distro=debian-11",
				Metadata: pkg.DpkgDBEntry{
					Package: "curl",
				},
			},
			expected: pkg.Package{
				PURL:    "pkg:deb/debian/curl@7.74.0-1.3+deb11u7?arch=amd64&distro=debian-11",
				Type:    pkg.DebPkg,
				Name:    "curl",
				Version: "7.74.0-1.3+deb11u7",
				Metadata: pkg.DpkgDBEntry{
					Package:      "curl",
					Architecture: "amd64",
				},
			},
		},
		{
			name: "deb populated metadata with arch preserved",
			in: pkg.Package{
				PURL: "pkg:deb/debian/curl@7.74.0-1.3+deb11u7?arch=amd64&distro=debian-11",
				Metadata: pkg.DpkgDBEntry{
					Package:      "curl",
					Architecture: "arm64",
				},
			},
			expected: pkg.Package{
				PURL:    "pkg:deb/debian/curl@7.74.0-1.3+deb11u7?arch=amd64&distro=debian-11",
				Type:    pkg.DebPkg,
				Name:    "curl",
				Version: "7.74.0-1.3+deb11u7",
				Metadata: pkg.DpkgDBEntry{
					Package:      "curl",
					Architecture: "arm64",
				},
			},
		},
		{
			name: "deb archive entry empty arch gets filled",
			in: pkg.Package{
				PURL: "pkg:deb/debian/curl@7.74.0-1.3+deb11u7?arch=amd64&distro=debian-11",
				Metadata: pkg.DpkgArchiveEntry{
					Package: "curl",
				},
			},
			expected: pkg.Package{
				PURL:    "pkg:deb/debian/curl@7.74.0-1.3+deb11u7?arch=amd64&distro=debian-11",
				Type:    pkg.DebPkg,
				Name:    "curl",
				Version: "7.74.0-1.3+deb11u7",
				Metadata: pkg.DpkgArchiveEntry{
					Package:      "curl",
					Architecture: "amd64",
				},
			},
		},
		{
			name: "deb archive entry with arch preserved",
			in: pkg.Package{
				PURL: "pkg:deb/debian/curl@7.74.0-1.3+deb11u7?arch=amd64&distro=debian-11",
				Metadata: pkg.DpkgArchiveEntry{
					Package:      "curl",
					Architecture: "arm64",
				},
			},
			expected: pkg.Package{
				PURL:    "pkg:deb/debian/curl@7.74.0-1.3+deb11u7?arch=amd64&distro=debian-11",
				Type:    pkg.DebPkg,
				Name:    "curl",
				Version: "7.74.0-1.3+deb11u7",
				Metadata: pkg.DpkgArchiveEntry{
					Package:      "curl",
					Architecture: "arm64",
				},
			},
		},
		// alpm cases
		{
			name: "alpm nil metadata gets arch set",
			in: pkg.Package{
				PURL: "pkg:alpm/arch/curl@7.88.1-1?arch=x86_64&distro=arch-rolling",
			},
			expected: pkg.Package{
				PURL:    "pkg:alpm/arch/curl@7.88.1-1?arch=x86_64&distro=arch-rolling",
				Type:    pkg.AlpmPkg,
				Name:    "curl",
				Version: "7.88.1-1",
				Metadata: pkg.AlpmDBEntry{
					Architecture: "x86_64",
				},
			},
		},
		{
			name: "alpm populated metadata empty arch gets filled",
			in: pkg.Package{
				PURL: "pkg:alpm/arch/curl@7.88.1-1?arch=x86_64&distro=arch-rolling",
				Metadata: pkg.AlpmDBEntry{
					Package: "curl",
				},
			},
			expected: pkg.Package{
				PURL:    "pkg:alpm/arch/curl@7.88.1-1?arch=x86_64&distro=arch-rolling",
				Type:    pkg.AlpmPkg,
				Name:    "curl",
				Version: "7.88.1-1",
				Metadata: pkg.AlpmDBEntry{
					Package:      "curl",
					Architecture: "x86_64",
				},
			},
		},
		{
			name: "alpm populated metadata with arch preserved",
			in: pkg.Package{
				PURL: "pkg:alpm/arch/curl@7.88.1-1?arch=x86_64&distro=arch-rolling",
				Metadata: pkg.AlpmDBEntry{
					Package:      "curl",
					Architecture: "aarch64",
				},
			},
			expected: pkg.Package{
				PURL:    "pkg:alpm/arch/curl@7.88.1-1?arch=x86_64&distro=arch-rolling",
				Type:    pkg.AlpmPkg,
				Name:    "curl",
				Version: "7.88.1-1",
				Metadata: pkg.AlpmDBEntry{
					Package:      "curl",
					Architecture: "aarch64",
				},
			},
		},
		// apk cases
		{
			name: "apk nil metadata gets arch set",
			in: pkg.Package{
				PURL: "pkg:apk/alpine/curl@7.83.1-r2?arch=aarch64&distro=alpine-3.16.2",
			},
			expected: pkg.Package{
				PURL:    "pkg:apk/alpine/curl@7.83.1-r2?arch=aarch64&distro=alpine-3.16.2",
				Type:    pkg.ApkPkg,
				Name:    "curl",
				Version: "7.83.1-r2",
				Metadata: pkg.ApkDBEntry{
					Architecture: "aarch64",
				},
			},
		},
		{
			name: "apk populated metadata empty arch gets filled",
			in: pkg.Package{
				PURL: "pkg:apk/alpine/curl@7.83.1-r2?arch=aarch64&distro=alpine-3.16.2",
				Metadata: pkg.ApkDBEntry{
					Package: "curl",
				},
			},
			expected: pkg.Package{
				PURL:    "pkg:apk/alpine/curl@7.83.1-r2?arch=aarch64&distro=alpine-3.16.2",
				Type:    pkg.ApkPkg,
				Name:    "curl",
				Version: "7.83.1-r2",
				Metadata: pkg.ApkDBEntry{
					Package:      "curl",
					Architecture: "aarch64",
				},
			},
		},
		{
			name: "apk populated metadata with arch preserved",
			in: pkg.Package{
				PURL: "pkg:apk/alpine/curl@7.83.1-r2?arch=aarch64&distro=alpine-3.16.2",
				Metadata: pkg.ApkDBEntry{
					Package:      "curl",
					Architecture: "x86_64",
				},
			},
			expected: pkg.Package{
				PURL:    "pkg:apk/alpine/curl@7.83.1-r2?arch=aarch64&distro=alpine-3.16.2",
				Type:    pkg.ApkPkg,
				Name:    "curl",
				Version: "7.83.1-r2",
				Metadata: pkg.ApkDBEntry{
					Package:      "curl",
					Architecture: "x86_64",
				},
			},
		},
		{
			name: "target-sw from CPE",
			in: pkg.Package{
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:amazon:opensearch:*:*:*:*:*:ruby:*:*", ""),
				},
			},
			expected: pkg.Package{
				CPEs: []cpe.CPE{
					cpe.Must("cpe:2.3:a:amazon:opensearch:*:*:*:*:*:ruby:*:*", ""),
				},
				Type: pkg.GemPkg,
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

func strRef(s string) *string {
	return &s
}
