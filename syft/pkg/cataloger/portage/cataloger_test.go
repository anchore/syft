package portage

import (
	"testing"

	"github.com/anchore/syft/syft/file"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	"github.com/go-test/deep"
)

func TestPortageCataloger(t *testing.T) {
	tests := []struct {
		name     string
		expected []pkg.Package
	}{
		{
			name: "go-case",
			expected: []pkg.Package{
				{
					Name:         "app-containers/skopeo",
					Version:      "1.5.1",
					FoundBy:      "portage-cataloger",
					Licenses:     []string{"Apache-2.0", "BSD", "BSD-2", "CC-BY-SA-4.0", "ISC", "MIT"},
					Type:         pkg.PortagePkg,
					MetadataType: pkg.PortageMetadataType,
					Metadata: pkg.PortageMetadata{
						Package:       "app-containers/skopeo",
						Version:       "1.5.1",
						InstalledSize: 27937835,
						Files: []pkg.PortageFileRecord{
							{
								Path: "/usr/bin/skopeo",
								Digest: &file.Digest{
									Algorithm: "md5",
									Value:     "376c02bd3b22804df8fdfdc895e7dbfb",
								},
							},
							{
								Path: "/etc/containers/policy.json",
								Digest: &file.Digest{
									Algorithm: "md5",
									Value:     "c01eb6950f03419e09d4fc88cb42ff6f",
								},
							},
							{
								Path: "/etc/containers/registries.d/default.yaml",
								Digest: &file.Digest{
									Algorithm: "md5",
									Value:     "e6e66cd3c24623e0667f26542e0e08f6",
								},
							},
							{
								Path: "/var/lib/atomic/sigstore/.keep_app-containers_skopeo-0",
								Digest: &file.Digest{
									Algorithm: "md5",
									Value:     "d41d8cd98f00b204e9800998ecf8427e",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			img := imagetest.GetFixtureImage(t, "docker-archive", "image-portage")

			s, err := source.NewFromImage(img, "")
			if err != nil {
				t.Fatal(err)
			}

			c := NewPortageCataloger()

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

			// test remaining fields...
			for _, d := range deep.Equal(actual, test.expected) {
				t.Errorf("diff: %+v", d)
			}

		})
	}

}
