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
			name:       "positive-redis-2.8.23",
			fixtureDir: "test-fixtures/classifiers/positive/redis-server-2.8.23",
			expected: pkg.Package{
				Name:      "redis",
				Version:   "2.8.23",
				Type:      "binary",
				PURL:      "pkg:generic/redis@2.8.23",
				Locations: singleLocation("redis-server"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "redis-binary",
				},
			},
		},
		{
			name:       "positive-redis-4.0.11",
			fixtureDir: "test-fixtures/classifiers/positive/redis-server-4.0.11",
			expected: pkg.Package{
				Name:      "redis",
				Version:   "4.0.11",
				Type:      "binary",
				PURL:      "pkg:generic/redis@4.0.11",
				Locations: singleLocation("redis-server"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "redis-binary",
				},
			},
		},
		{
			name:       "positive-redis-5.0.0",
			fixtureDir: "test-fixtures/classifiers/positive/redis-server-5.0.0",
			expected: pkg.Package{
				Name:      "redis",
				Version:   "5.0.0",
				Type:      "binary",
				PURL:      "pkg:generic/redis@5.0.0",
				Locations: singleLocation("redis-server"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "redis-binary",
				},
			},
		},
		{
			name:       "positive-redis-6.0.16",
			fixtureDir: "test-fixtures/classifiers/positive/redis-server-6.0.16",
			expected: pkg.Package{
				Name:      "redis",
				Version:   "6.0.16",
				Type:      "binary",
				PURL:      "pkg:generic/redis@6.0.16",
				Locations: singleLocation("redis-server"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "redis-binary",
				},
			},
		},
		{
			name:       "positive-redis-7.0.0",
			fixtureDir: "test-fixtures/classifiers/positive/redis-server-7.0.0",
			expected: pkg.Package{
				Name:      "redis",
				Version:   "7.0.0",
				Type:      "binary",
				PURL:      "pkg:generic/redis@7.0.0",
				Locations: singleLocation("redis-server"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "redis-binary",
				},
			},
		},
		{
			name:       "positive-libpython3.7.so",
			fixtureDir: "test-fixtures/classifiers/positive",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.7.4a-vZ9",
				PURL:      "pkg:generic/python@3.7.4a-vZ9",
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
				PURL:      "pkg:generic/python@3.6.3a-vZ9",
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
				PURL:      "pkg:generic/python@3.9-aZ5",
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
				PURL:      "pkg:generic/go@1.14",
				Locations: singleLocation("go"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "go-binary",
				},
			},
		},
		{
			name:       "positive-node",
			fixtureDir: "test-fixtures/classifiers/positive",
			expected: pkg.Package{
				Name:      "node",
				Version:   "19.2.1",
				PURL:      "pkg:generic/node@19.2.1",
				Locations: singleLocation("node"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "nodejs-binary",
				},
			},
		},
		{
			name:       "positive-go-hint",
			fixtureDir: "test-fixtures/classifiers/positive",
			expected: pkg.Package{
				Name:      "go",
				Version:   "1.15",
				PURL:      "pkg:generic/go@1.15",
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
		{
			name:       "positive-java-openjdk",
			fixtureDir: "test-fixtures/classifiers/positive/openjdk",
			expected: pkg.Package{
				Name:      "java",
				Version:   "1.8.0_352-b08",
				Type:      "binary",
				PURL:      "pkg:generic/java@1.8.0_352-b08",
				Locations: singleLocation("java"),
				Metadata: pkg.BinaryMetadata{
					Classifier:  "java-binary-openjdk",
					VirtualPath: "java",
				},
			},
		},
		{
			name:       "positive-java-openjdk-lts",
			fixtureDir: "test-fixtures/classifiers/positive/openjdk-lts",
			expected: pkg.Package{
				Name:      "java",
				Version:   "11.0.17+8-LTS",
				Type:      "binary",
				PURL:      "pkg:generic/java@11.0.17+8-LTS",
				Locations: singleLocation("java"),
				Metadata: pkg.BinaryMetadata{
					Classifier:  "java-binary-openjdk",
					VirtualPath: "java",
				},
			},
		},
		{
			name:       "positive-java-oracle",
			fixtureDir: "test-fixtures/classifiers/positive/oracle",
			expected: pkg.Package{
				Name:      "java",
				Version:   "19.0.1+10-21",
				Type:      "binary",
				PURL:      "pkg:generic/java@19.0.1+10-21",
				Locations: singleLocation("java"),
				Metadata: pkg.BinaryMetadata{
					Classifier:  "java-binary-oracle",
					VirtualPath: "java",
				},
			},
		},
		{
			name:       "positive-java-oracle-macos",
			fixtureDir: "test-fixtures/classifiers/positive/oracle-macos",
			expected: pkg.Package{
				Name:      "java",
				Version:   "19.0.1+10-21",
				Type:      "binary",
				PURL:      "pkg:generic/java@19.0.1+10-21",
				Locations: singleLocation("java"),
				Metadata: pkg.BinaryMetadata{
					Classifier:  "java-binary-oracle",
					VirtualPath: "java",
				},
			},
		},
		{
			name:       "positive-java-ibm",
			fixtureDir: "test-fixtures/classifiers/positive/ibm",
			expected: pkg.Package{
				Name:      "java",
				Version:   "1.8.0-foreman_2022_09_22_15_30-b00",
				Type:      "binary",
				PURL:      "pkg:generic/java@1.8.0-foreman_2022_09_22_15_30-b00",
				Locations: singleLocation("java"),
				Metadata: pkg.BinaryMetadata{
					Classifier:  "java-binary-ibm",
					VirtualPath: "java",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewCataloger()

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
			c := NewCataloger()

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
	c := NewCataloger()

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
		expected.PURL != p.PURL ||
		meta1.Classifier != meta2.Classifier {
		assert.Failf(t, "packages not equal", "%v != %v", expected, p)
	}
}
