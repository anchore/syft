package binary

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func TestClassifierCataloger_DefaultClassifiers_PositiveCases(t *testing.T) {
	tests := []struct {
		name       string
		fixtureDir string
		expected   pkg.Package
	}{
		{
			name:       "positive-libpython3.7.so",
			fixtureDir: "test-fixtures/classifiers/positive",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.7.4a-vZ9",
				Locations: singleLocation("libpython3.7.so"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "python-binary-lib",
				},
			},
		},
		{
			name:       "positive-python3.6",
			fixtureDir: "test-fixtures/classifiers/positive",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.6.3a-vZ9",
				Locations: singleLocation("python3.6"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "python-binary",
				},
			},
		},
		{
			name:       "positive-patchlevel.h",
			fixtureDir: "test-fixtures/classifiers/positive",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.9-aZ5",
				Locations: singleLocation("patchlevel.h"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "cpython-source",
				},
			},
		},
		{
			name:       "positive-go",
			fixtureDir: "test-fixtures/classifiers/positive",
			expected: pkg.Package{
				Name:      "go",
				Version:   "1.14",
				Locations: singleLocation("go"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "go-binary",
				},
			},
		},
		{
			name:       "positive-go-hint",
			fixtureDir: "test-fixtures/classifiers/positive",
			expected: pkg.Package{
				Name:      "go",
				Version:   "1.15",
				Locations: singleLocation("VERSION"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "go-binary-hint",
				},
			},
		},
		{
			name:       "positive-busybox",
			fixtureDir: "test-fixtures/classifiers/positive",
			expected: pkg.Package{
				Name:      "busybox",
				Version:   "3.33.3",
				Locations: singleLocation("["), // note: busybox is a link to [
				Metadata: pkg.BinaryMetadata{
					Classifier:  "busybox-binary",
					VirtualPath: "busybox",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewBinaryCataloger()

			src, err := source.NewFromDirectory(test.fixtureDir)
			require.NoError(t, err)

			resolver, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			packages, _, err := c.Catalog(resolver)
			require.NoError(t, err)

			ok := false
			for _, p := range packages {
				if test.expected.Locations.ToSlice()[0].RealPath == p.Locations.ToSlice()[0].RealPath {
					ok = true
					assertPackagesAreEqual(t, test.expected, p)
				}
			}

			if !ok {
				t.Fatalf("could not find test location=%q", test.expected.Locations.ToSlice()[0].RealPath)
			}

		})
	}
}

func TestClassifierCataloger_DefaultClassifiers_PositiveCases_Image(t *testing.T) {
	tests := []struct {
		name         string
		fixtureImage string
		expected     pkg.Package
	}{
		{
			name:         "busybox-regression",
			fixtureImage: "image-busybox",
			expected: pkg.Package{
				Name:      "busybox",
				Version:   "1.35.0",
				Locations: singleLocation("/bin/["),
				Metadata: pkg.BinaryMetadata{
					Classifier:  "busybox-binary",
					VirtualPath: "/bin/busybox",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewBinaryCataloger()

			img := imagetest.GetFixtureImage(t, "docker-archive", test.fixtureImage)
			src, err := source.NewFromImage(img, "test-img")
			require.NoError(t, err)

			resolver, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			packages, _, err := c.Catalog(resolver)
			require.NoError(t, err)

			ok := false
			for _, p := range packages {
				if test.expected.Locations.ToSlice()[0].RealPath == p.Locations.ToSlice()[0].RealPath {
					ok = true
					assertPackagesAreEqual(t, test.expected, p)
				}
			}

			if !ok {
				t.Fatalf("could not find test location=%q", test.expected.Locations.ToSlice()[0].RealPath)
			}

		})
	}
}

func TestClassifierCataloger_DefaultClassifiers_NegativeCases(t *testing.T) {
	c := NewBinaryCataloger()

	src, err := source.NewFromDirectory("test-fixtures/classifiers/negative")
	assert.NoError(t, err)

	resolver, err := src.FileResolver(source.SquashedScope)
	assert.NoError(t, err)

	actualResults, _, err := c.Catalog(resolver)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(actualResults))
}

func singleLocation(s string) source.LocationSet {
	return source.NewLocationSet(source.NewLocation(s))
}

func assertPackagesAreEqual(t *testing.T, expected pkg.Package, p pkg.Package) {
	meta1 := expected.Metadata.(pkg.BinaryMetadata)
	meta2 := p.Metadata.(pkg.BinaryMetadata)
	if expected.Name != p.Name ||
		expected.Version != p.Version ||
		meta1.Classifier != meta2.Classifier {
		assert.Failf(t, "packages not equal", "%v != %v", expected, p)
	}
}
