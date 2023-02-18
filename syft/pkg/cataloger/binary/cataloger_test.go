package binary

import (
	"errors"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

func Test_Cataloger_DefaultClassifiers_PositiveCases(t *testing.T) {
	tests := []struct {
		name       string
		fixtureDir string
		expected   pkg.Package
	}{
		{
			name:       "positive-postgresql-15beta4",
			fixtureDir: "test-fixtures/classifiers/positive/postgresql-15beta4",
			expected: pkg.Package{
				Name:      "postgresql",
				Version:   "15beta4",
				Type:      "binary",
				PURL:      "pkg:generic/postgresql@15beta4",
				Locations: singleLocation("postgres"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "postgresql-binary",
				},
			},
		},
		{
			name:       "positive-postgresql-15.1",
			fixtureDir: "test-fixtures/classifiers/positive/postgresql-15.1",
			expected: pkg.Package{
				Name:      "postgresql",
				Version:   "15.1",
				Type:      "binary",
				PURL:      "pkg:generic/postgresql@15.1",
				Locations: singleLocation("postgres"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "postgresql-binary",
				},
			},
		},
		{
			name:       "positive-postgresql-9.6.24",
			fixtureDir: "test-fixtures/classifiers/positive/postgresql-9.6.24",
			expected: pkg.Package{
				Name:      "postgresql",
				Version:   "9.6.24",
				Type:      "binary",
				PURL:      "pkg:generic/postgresql@9.6.24",
				Locations: singleLocation("postgres"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "postgresql-binary",
				},
			},
		},
		{
			name:       "positive-postgresql-9.5alpha1",
			fixtureDir: "test-fixtures/classifiers/positive/postgresql-9.5alpha1",
			expected: pkg.Package{
				Name:      "postgresql",
				Version:   "9.5alpha1",
				Type:      "binary",
				PURL:      "pkg:generic/postgresql@9.5alpha1",
				Locations: singleLocation("postgres"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "postgresql-binary",
				},
			},
		},
		{
			name:       "positive-traefik-2.9.6",
			fixtureDir: "test-fixtures/classifiers/positive/traefik-2.9.6",
			expected: pkg.Package{
				Name:      "traefik",
				Version:   "2.9.6",
				Type:      "binary",
				PURL:      "pkg:generic/traefik@2.9.6",
				Locations: singleLocation("traefik"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "traefik-binary",
				},
			},
		},
		{
			name:       "positive-traefik-1.7.34",
			fixtureDir: "test-fixtures/classifiers/positive/traefik-1.7.34",
			expected: pkg.Package{
				Name:      "traefik",
				Version:   "1.7.34",
				Type:      "binary",
				PURL:      "pkg:generic/traefik@1.7.34",
				Locations: singleLocation("traefik"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "traefik-binary",
				},
			},
		},
		{
			name:       "positive-memcached-1.6.18",
			fixtureDir: "test-fixtures/classifiers/positive/memcached-1.6.18",
			expected: pkg.Package{
				Name:      "memcached",
				Version:   "1.6.18",
				Type:      "binary",
				PURL:      "pkg:generic/memcached@1.6.18",
				Locations: singleLocation("memcached"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "memcached-binary",
				},
			},
		},
		{
			name:       "positive-httpd-2.4.54",
			fixtureDir: "test-fixtures/classifiers/positive/httpd-2.4.54",
			expected: pkg.Package{
				Name:      "httpd",
				Version:   "2.4.54",
				Type:      "binary",
				PURL:      "pkg:generic/httpd@2.4.54",
				Locations: singleLocation("httpd"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "httpd-binary",
				},
			},
		},
		{
			name:       "positive-php-cli-8.2.1",
			fixtureDir: "test-fixtures/classifiers/positive/php-cli-8.2.1",
			expected: pkg.Package{
				Name:      "php-cli",
				Version:   "8.2.1",
				Type:      "binary",
				PURL:      "pkg:generic/php-cli@8.2.1",
				Locations: singleLocation("php"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "php-cli-binary",
				},
			},
		},
		{
			name:       "positive-php-fpm-8.2.1",
			fixtureDir: "test-fixtures/classifiers/positive/php-fpm-8.2.1",
			expected: pkg.Package{
				Name:      "php-fpm",
				Version:   "8.2.1",
				Type:      "binary",
				PURL:      "pkg:generic/php-fpm@8.2.1",
				Locations: singleLocation("php-fpm"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "php-fpm-binary",
				},
			},
		},
		{
			name:       "positive-php-apache-8.2.1",
			fixtureDir: "test-fixtures/classifiers/positive/php-apache-8.2.1",
			expected: pkg.Package{
				Name:      "libphp",
				Version:   "8.2.1",
				Type:      "binary",
				PURL:      "pkg:generic/php@8.2.1",
				Locations: singleLocation("libphp.so"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "php-apache-binary",
				},
			},
		},
		{
			name:       "positive-perl-5.12.5",
			fixtureDir: "test-fixtures/classifiers/positive/perl-5.12.5",
			expected: pkg.Package{
				Name:      "perl",
				Version:   "5.12.5",
				Type:      "binary",
				PURL:      "pkg:generic/perl@5.12.5",
				Locations: singleLocation("perl"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "perl-binary",
				},
			},
		},
		{
			name:       "positive-perl-5.20.0",
			fixtureDir: "test-fixtures/classifiers/positive/perl-5.20.0",
			expected: pkg.Package{
				Name:      "perl",
				Version:   "5.20.0",
				Type:      "binary",
				PURL:      "pkg:generic/perl@5.20.0",
				Locations: singleLocation("perl"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "perl-binary",
				},
			},
		},
		{
			name:       "positive-perl-5.37.8",
			fixtureDir: "test-fixtures/classifiers/positive/perl-5.37.8",
			expected: pkg.Package{
				Name:      "perl",
				Version:   "5.37.8",
				Type:      "binary",
				PURL:      "pkg:generic/perl@5.37.8",
				Locations: singleLocation("perl"),
				Metadata: pkg.BinaryMetadata{
					Classifier: "perl-binary",
				},
			},
		},
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

func Test_Cataloger_DefaultClassifiers_PositiveCases_Image(t *testing.T) {
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

type panicyResolver struct {
	searchCalled bool
}

func (p *panicyResolver) FilesByExtension(_ ...string) ([]source.Location, error) {
	p.searchCalled = true
	return nil, errors.New("not implemented")
}

func (p *panicyResolver) FilesByBasename(_ ...string) ([]source.Location, error) {
	p.searchCalled = true
	return nil, errors.New("not implemented")
}

func (p *panicyResolver) FilesByBasenameGlob(_ ...string) ([]source.Location, error) {
	p.searchCalled = true
	return nil, errors.New("not implemented")
}

func (p *panicyResolver) FileContentsByLocation(_ source.Location) (io.ReadCloser, error) {
	p.searchCalled = true
	return nil, errors.New("not implemented")
}

func (p *panicyResolver) HasPath(s string) bool {
	return true
}

func (p *panicyResolver) FilesByPath(_ ...string) ([]source.Location, error) {
	p.searchCalled = true
	return nil, errors.New("not implemented")
}

func (p *panicyResolver) FilesByGlob(_ ...string) ([]source.Location, error) {
	p.searchCalled = true
	return nil, errors.New("not implemented")
}

func (p *panicyResolver) FilesByMIMEType(_ ...string) ([]source.Location, error) {
	p.searchCalled = true
	return nil, errors.New("not implemented")
}

func (p *panicyResolver) RelativeFileByPath(_ source.Location, _ string) *source.Location {
	return nil
}

func (p *panicyResolver) AllLocations() <-chan source.Location {
	return nil
}

func (p *panicyResolver) FileMetadataByLocation(_ source.Location) (source.FileMetadata, error) {
	return source.FileMetadata{}, errors.New("not implemented")
}

func Test_Cataloger_ResilientToErrors(t *testing.T) {
	c := NewCataloger()

	resolver := &panicyResolver{}
	_, _, err := c.Catalog(resolver)
	assert.NoError(t, err)
	assert.True(t, resolver.searchCalled)
}
