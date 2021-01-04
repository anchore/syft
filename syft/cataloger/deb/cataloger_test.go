package deb

import (
	"testing"

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
				"libpam-runtime": {"/var/lib/dpkg/status", "/var/lib/dpkg/info/libpam-runtime.md5sums", "/usr/share/doc/libpam-runtime/copyright"},
			},
			expected: []pkg.Package{
				{
					Name:         "libpam-runtime",
					Version:      "1.1.8-3.6",
					FoundBy:      "dpkgdb-cataloger",
					Licenses:     []string{"GPL-2", "LGPL-2.1"},
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
							{Path: "/lib/x86_64-linux-gnu/libz.so.1.2.11", MD5: "55f905631797551d4d936a34c7e73474"},
							{Path: "/usr/share/doc/zlib1g/changelog.Debian.gz", MD5: "cede84bda30d2380217f97753c8ccf3a"},
							{Path: "/usr/share/doc/zlib1g/changelog.gz", MD5: "f3c9dafa6da7992c47328b4464f6d122"},
							{Path: "/usr/share/doc/zlib1g/copyright", MD5: "a4fae96070439a5209a62ae5b8017ab2"},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			img, cleanup := imagetest.GetFixtureImage(t, "docker-archive", "image-dpkg")
			defer cleanup()

			s, err := source.NewFromImage(img, source.SquashedScope, "")
			if err != nil {
				t.Fatal(err)
			}

			c := NewDpkgdbCataloger()

			actual, err := c.Catalog(s.Resolver)
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
				var sourcesList = make([]string, len(a.Locations))
				for i, s := range a.Locations {
					sourcesList[i] = s.Path
				}
				a.Locations = nil

				for _, d := range deep.Equal(sourcesList, test.sources[a.Name]) {
					t.Errorf("diff: %+v", d)
				}
			}

			// test remaining fields...
			for _, d := range deep.Equal(actual, test.expected) {
				t.Errorf("diff: %+v", d)
			}

		})
	}

}
