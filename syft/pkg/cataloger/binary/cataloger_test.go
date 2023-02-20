package binary

import (
	"errors"
	"fmt"
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
				Locations: locations("postgres"),
				Metadata:  metadata("postgresql-binary"),
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
				Locations: locations("postgres"),
				Metadata:  metadata("postgresql-binary"),
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
				Locations: locations("postgres"),
				Metadata:  metadata("postgresql-binary"),
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
				Locations: locations("postgres"),
				Metadata:  metadata("postgresql-binary"),
			},
		},
		{
			name:       "positive-python-duplicates",
			fixtureDir: "test-fixtures/classifiers/positive/python-duplicates",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.8.16",
				Type:      "binary",
				PURL:      "pkg:generic/python@3.8.16",
				Locations: locations("dir/python3.8", "python3.8", "libpython3.8.so", "patchlevel.h"),
				Metadata: pkg.BinaryMetadata{
					Matches: []pkg.ClassifierMatch{
						match("python-binary", "dir/python3.8"),
						match("python-binary", "python3.8"),
						match("python-binary-lib", "libpython3.8.so"),
						match("cpython-source", "patchlevel.h"),
					},
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
				Locations: locations("traefik"),
				Metadata:  metadata("traefik-binary"),
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
				Locations: locations("traefik"),
				Metadata:  metadata("traefik-binary"),
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
				Locations: locations("memcached"),
				Metadata:  metadata("memcached-binary"),
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
				Locations: locations("httpd"),
				Metadata:  metadata("httpd-binary"),
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
				Locations: locations("php"),
				Metadata:  metadata("php-cli-binary"),
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
				Locations: locations("php-fpm"),
				Metadata:  metadata("php-fpm-binary"),
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
				Locations: locations("libphp.so"),
				Metadata:  metadata("php-apache-binary"),
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
				Locations: locations("perl"),
				Metadata:  metadata("perl-binary"),
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
				Locations: locations("perl"),
				Metadata:  metadata("perl-binary"),
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
				Locations: locations("perl"),
				Metadata:  metadata("perl-binary"),
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
				Locations: locations("redis-server"),
				Metadata:  metadata("redis-binary"),
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
				Locations: locations("redis-server"),
				Metadata:  metadata("redis-binary"),
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
				Locations: locations("redis-server"),
				Metadata:  metadata("redis-binary"),
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
				Locations: locations("redis-server"),
				Metadata:  metadata("redis-binary"),
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
				Locations: locations("redis-server"),
				Metadata:  metadata("redis-binary"),
			},
		},
		{
			name:       "positive-libpython3.7.so",
			fixtureDir: "test-fixtures/classifiers/positive/python-binary-lib-3.7",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.7.4a-vZ9",
				PURL:      "pkg:generic/python@3.7.4a-vZ9",
				Locations: locations("libpython3.7.so"),
				Metadata:  metadata("python-binary-lib"),
			},
		},
		{
			name:       "positive-python3.6",
			fixtureDir: "test-fixtures/classifiers/positive/python-binary-3.6",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.6.3a-vZ9",
				PURL:      "pkg:generic/python@3.6.3a-vZ9",
				Locations: locations("python3.6"),
				Metadata:  metadata("python-binary"),
			},
		},
		{
			name:       "positive-patchlevel.h",
			fixtureDir: "test-fixtures/classifiers/positive/python-source-3.9",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.9-aZ5",
				PURL:      "pkg:generic/python@3.9-aZ5",
				Locations: locations("patchlevel.h"),
				Metadata:  metadata("cpython-source"),
			},
		},
		{
			name:       "positive-go",
			fixtureDir: "test-fixtures/classifiers/positive/go-1.14",
			expected: pkg.Package{
				Name:      "go",
				Version:   "1.14",
				PURL:      "pkg:generic/go@1.14",
				Locations: locations("go"),
				Metadata:  metadata("go-binary"),
			},
		},
		{
			name:       "positive-node",
			fixtureDir: "test-fixtures/classifiers/positive/node-19.2.1",
			expected: pkg.Package{
				Name:      "node",
				Version:   "19.2.1",
				PURL:      "pkg:generic/node@19.2.1",
				Locations: locations("node"),
				Metadata:  metadata("nodejs-binary"),
			},
		},
		{
			name:       "positive-go-hint",
			fixtureDir: "test-fixtures/classifiers/positive/go-hint-1.15",
			expected: pkg.Package{
				Name:      "go",
				Version:   "1.15",
				PURL:      "pkg:generic/go@1.15",
				Locations: locations("VERSION"),
				Metadata:  metadata("go-binary-hint"),
			},
		},
		{
			name:       "positive-busybox",
			fixtureDir: "test-fixtures/classifiers/positive/busybox-3.33.3",
			expected: pkg.Package{
				Name:      "busybox",
				Version:   "3.33.3",
				Locations: locations("["), // note: busybox is a link to [
				Metadata:  metadata("busybox-binary", "[", "busybox"),
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
				Locations: locations("java"),
				Metadata:  metadata("java-binary-openjdk", "java"),
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
				Locations: locations("java"),
				Metadata:  metadata("java-binary-openjdk", "java"),
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
				Locations: locations("java"),
				Metadata:  metadata("java-binary-oracle", "java"),
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
				Locations: locations("java"),
				Metadata:  metadata("java-binary-oracle", "java"),
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
				Locations: locations("java"),
				Metadata:  metadata("java-binary-ibm", "java"),
			},
		},
		{
			name:       "positive-rust-1.50.0-macos",
			fixtureDir: "test-fixtures/classifiers/positive/rust-1.50.0",
			expected: pkg.Package{
				Name:      "rust",
				Version:   "1.50.0",
				Type:      "binary",
				PURL:      "pkg:generic/rust@1.50.0",
				Locations: locations("lib/rustlib/aarch64-apple-darwin/lib/libstd-f6f9eec1635e636a.dylib"),
				Metadata:  metadata("rust-standard-library-macos"),
			},
		},
		{
			name:       "positive-rust-1.67.1-macos",
			fixtureDir: "test-fixtures/classifiers/positive/rust-1.67.1/toolchains/stable-aarch64-apple-darwin",
			expected: pkg.Package{
				Name:      "rust",
				Version:   "1.67.1",
				Type:      "binary",
				PURL:      "pkg:generic/rust@1.67.1",
				Locations: locations("lib/libstd-16f2b65e77054c42.dylib"),
				Metadata:  metadata("rust-standard-library-macos"),
			},
		},
		{
			name:       "positive-rust-1.67.1-linux",
			fixtureDir: "test-fixtures/classifiers/positive/rust-1.67.1/toolchains/stable-x86_64-unknown-linux-musl",
			expected: pkg.Package{
				Name:      "rust",
				Version:   "1.67.1",
				Type:      "binary",
				PURL:      "pkg:generic/rust@1.67.1",
				Locations: locations("lib/libstd-86aefecbddda356d.so"),
				Metadata:  metadata("rust-standard-library-linux"),
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

			for _, p := range packages {
				expectedLocations := test.expected.Locations.ToSlice()
				gotLocations := p.Locations.ToSlice()
				require.Len(t, gotLocations, len(expectedLocations))

				for i, expectedLocation := range expectedLocations {
					gotLocation := gotLocations[i]
					if expectedLocation.RealPath != gotLocation.RealPath {
						t.Fatalf("locations do not match; expected: %v got: %v", expectedLocations, gotLocations)
					}
				}

				assertPackagesAreEqual(t, test.expected, p)
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
				Locations: locations("/bin/["),
				Metadata:  metadata("busybox-binary", "/bin/[", "/bin/busybox"),
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

			for _, p := range packages {
				expectedLocations := test.expected.Locations.ToSlice()
				gotLocations := p.Locations.ToSlice()
				require.Len(t, gotLocations, len(expectedLocations))

				for i, expectedLocation := range expectedLocations {
					gotLocation := gotLocations[i]
					if expectedLocation.RealPath != gotLocation.RealPath {
						t.Fatalf("locations do not match; expected: %v got: %v", expectedLocations, gotLocations)
					}
				}

				assertPackagesAreEqual(t, test.expected, p)
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

func locations(locations ...string) source.LocationSet {
	var locs []source.Location
	for _, s := range locations {
		locs = append(locs, source.NewLocation(s))
	}
	return source.NewLocationSet(locs...)
}

// metadata paths are: realPath, virtualPath
func metadata(classifier string, paths ...string) pkg.BinaryMetadata {
	return pkg.BinaryMetadata{
		Matches: []pkg.ClassifierMatch{
			match(classifier, paths...),
		},
	}
}

// match paths are: realPath, virtualPath
func match(classifier string, paths ...string) pkg.ClassifierMatch {
	realPath := ""
	if len(paths) > 0 {
		realPath = paths[0]
	}
	virtualPath := ""
	if len(paths) > 1 {
		virtualPath = paths[1]
	}
	return pkg.ClassifierMatch{
		Classifier: classifier,
		Location: source.Location{
			Coordinates: source.Coordinates{
				RealPath: realPath,
			},
			VirtualPath: virtualPath,
		},
	}
}

func assertPackagesAreEqual(t *testing.T, expected pkg.Package, p pkg.Package) {
	m1 := expected.Metadata.(pkg.BinaryMetadata).Matches
	m2 := p.Metadata.(pkg.BinaryMetadata).Matches
	matches := true
	if len(m1) == len(m2) {
		for i, m1 := range m1 {
			m2 := m2[i]
			if m1.Classifier != m2.Classifier {
				matches = false
				break
			}
			if m1.Location.RealPath != "" && m1.Location.RealPath != m2.Location.RealPath {
				matches = false
				break
			}
			if m1.Location.VirtualPath != "" && m1.Location.VirtualPath != m2.Location.VirtualPath {
				matches = false
				break
			}
		}
	} else {
		matches = false
	}
	if expected.Name != p.Name ||
		expected.Version != p.Version ||
		expected.PURL != p.PURL ||
		!matches {
		assert.Failf(t, "packages not equal", "%v != %v", stringifyPkg(expected), stringifyPkg(p))
	}
}

func stringifyPkg(p pkg.Package) string {
	matches := p.Metadata.(pkg.BinaryMetadata).Matches
	return fmt.Sprintf("(name=%s, version=%s, purl=%s, matches=%+v)", p.Name, p.Version, p.PURL, matches)
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

func (p *panicyResolver) HasPath(_ string) bool {
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

var _ source.FileResolver = (*panicyResolver)(nil)

func Test_Cataloger_ResilientToErrors(t *testing.T) {
	c := NewCataloger()

	resolver := &panicyResolver{}
	_, _, err := c.Catalog(resolver)
	assert.NoError(t, err)
	assert.True(t, resolver.searchCalled)
}
