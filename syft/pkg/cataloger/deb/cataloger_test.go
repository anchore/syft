package deb

import (
	"github.com/stretchr/testify/assert"
	"testing"

	"github.com/anchore/syft/syft/file"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/go-test/deep"
)

func TestDpkgCataloger(t *testing.T) {
	tests := []struct {
		name     string
		sources  map[string][]string
		expected []pkg.Package
	}{
		{
			name: "go-case",
			sources: map[string][]string{
				"libpam-runtime": {
					"/var/lib/dpkg/status",
					"/var/lib/dpkg/info/libpam-runtime.md5sums",
					"/var/lib/dpkg/info/libpam-runtime.conffiles",
					"/usr/share/doc/libpam-runtime/copyright",
				},
			},
			expected: []pkg.Package{
				{
					Name:         "libpam-runtime",
					Version:      "1.1.8-3.6",
					FoundBy:      "dpkgdb-cataloger",
					Licenses:     []string{"GPL-1", "GPL-2", "LGPL-2.1"},
					Type:         pkg.DebPkg,
					MetadataType: pkg.DpkgMetadataType,
					Metadata: pkg.DpkgMetadata{
						Package:       "libpam-runtime",
						Source:        "pam",
						Version:       "1.1.8-3.6",
						Architecture:  "all",
						Maintainer:    "Steve Langasek <vorlon@debian.org>",
						InstalledSize: 1016,
						Files: []pkg.DpkgFileRecord{
							{
								Path: "/etc/pam.conf",
								Digest: &file.Digest{
									Algorithm: "md5",
									Value:     "87fc76f18e98ee7d3848f6b81b3391e5",
								},
								IsConfigFile: true,
							},
							{
								Path: "/etc/pam.d/other",
								Digest: &file.Digest{
									Algorithm: "md5",
									Value:     "31aa7f2181889ffb00b87df4126d1701",
								},
								IsConfigFile: true,
							},
							{Path: "/lib/x86_64-linux-gnu/libz.so.1.2.11", Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "55f905631797551d4d936a34c7e73474",
							}},
							{Path: "/usr/share/doc/zlib1g/changelog.Debian.gz", Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "cede84bda30d2380217f97753c8ccf3a",
							}},
							{Path: "/usr/share/doc/zlib1g/changelog.gz", Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "f3c9dafa6da7992c47328b4464f6d122",
							}},
							{Path: "/usr/share/doc/zlib1g/copyright", Digest: &file.Digest{
								Algorithm: "md5",
								Value:     "a4fae96070439a5209a62ae5b8017ab2",
							}},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			img := imagetest.GetFixtureImage(t, "docker-archive", "image-dpkg")

			s, err := source.NewFromImage(img, "")
			if err != nil {
				t.Fatal(err)
			}

			c := NewDpkgdbCataloger()

			resolver, err := s.FileResolver(source.SquashedScope)
			if err != nil {
				t.Errorf("could not get resolver error: %+v", err)
			}

			actual, _, err := c.Catalog(resolver)
			if err != nil {
				t.Fatalf("failed to catalog: %+v", err)
			}

			if len(actual) != len(test.expected) {
				for _, a := range actual {
					t.Logf("   %+v", a)
				}
				t.Fatalf("unexpected package count: %d!=%d", len(actual), len(test.expected))
			}

			// test sources...
			for idx := range actual {
				a := &actual[idx]
				// we will test the sources separately
				var sourcesList = make([]string, len(a.Locations.ToSlice()))
				for i, s := range a.Locations.ToSlice() {
					sourcesList[i] = s.RealPath
				}
				a.Locations = source.NewLocationSet()

				assert.ElementsMatch(t, sourcesList, test.sources[a.Name])
			}

			// test remaining fields...
			for _, d := range deep.Equal(actual, test.expected) {
				t.Errorf("diff: %+v", d)
			}

		})
	}

}
