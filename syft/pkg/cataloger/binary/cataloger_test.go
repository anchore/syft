package binary

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/file"
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
			name:       "positive-haproxy-1.5.14",
			fixtureDir: "test-fixtures/classifiers/positive/haproxy-1.5.14",
			expected: pkg.Package{
				Name:      "haproxy",
				Version:   "1.5.14",
				Type:      "binary",
				PURL:      "pkg:generic/haproxy@1.5.14",
				Locations: locations("haproxy"),
				Metadata:  metadata("haproxy-binary"),
			},
		},
		{
			name:       "positive-haproxy-1.8.22",
			fixtureDir: "test-fixtures/classifiers/positive/haproxy-1.8.22",
			expected: pkg.Package{
				Name:      "haproxy",
				Version:   "1.8.22",
				Type:      "binary",
				PURL:      "pkg:generic/haproxy@1.8.22",
				Locations: locations("haproxy"),
				Metadata:  metadata("haproxy-binary"),
			},
		},
		{
			name:       "positive-haproxy-2.7.3",
			fixtureDir: "test-fixtures/classifiers/positive/haproxy-2.7.3",
			expected: pkg.Package{
				Name:      "haproxy",
				Version:   "2.7.3",
				Type:      "binary",
				PURL:      "pkg:generic/haproxy@2.7.3",
				Locations: locations("haproxy"),
				Metadata:  metadata("haproxy-binary"),
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
			name:       "positive-helm-3.11.1",
			fixtureDir: "test-fixtures/classifiers/dynamic/helm-3.11.1",
			expected: pkg.Package{
				Name:      "helm",
				Version:   "3.11.1",
				Type:      "binary",
				PURL:      "pkg:golang/helm.sh/helm@3.11.1",
				Locations: locations("helm"),
				Metadata:  metadata("helm"),
			},
		},
		{
			name:       "positive-helm-3.10.3",
			fixtureDir: "test-fixtures/classifiers/dynamic/helm-3.10.3",
			expected: pkg.Package{
				Name:      "helm",
				Version:   "3.10.3",
				Type:      "binary",
				PURL:      "pkg:golang/helm.sh/helm@3.10.3",
				Locations: locations("helm"),
				Metadata:  metadata("helm"),
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
				Version:   "3.7.4",
				PURL:      "pkg:generic/python@3.7.4",
				Locations: locations("libpython3.7.so"),
				Metadata:  metadata("python-binary-lib"),
			},
		},
		{
			name:       "positive-python-3.11.2-from-shared-lib",
			fixtureDir: "test-fixtures/classifiers/dynamic/python-binary-shared-lib-3.11",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.11.2",
				PURL:      "pkg:generic/python@3.11.2",
				Locations: locations("python3", "libpython3.11.so.1.0"),
				Metadata: pkg.BinaryMetadata{
					Matches: []pkg.ClassifierMatch{
						match("python-binary", "python3"),
						match("python-binary", "libpython3.11.so.1.0"),
						match("python-binary-lib", "libpython3.11.so.1.0"),
					},
				},
			},
		},
		{
			name:       "positive-python-3.9-from-shared-redhat-lib",
			fixtureDir: "test-fixtures/classifiers/dynamic/python-binary-shared-lib-redhat-3.9",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.9.13",
				PURL:      "pkg:generic/python@3.9.13",
				Locations: locations("python3.9", "libpython3.9.so.1.0"),
				Metadata: pkg.BinaryMetadata{
					Matches: []pkg.ClassifierMatch{
						match("python-binary", "python3.9"),
						match("python-binary", "libpython3.9.so.1.0"),
						match("python-binary-lib", "libpython3.9.so.1.0"),
					},
				},
			},
		},
		{
			name:       "positive-python-binary-with-version-3.9",
			fixtureDir: "test-fixtures/classifiers/dynamic/python-binary-with-version-3.9",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.9.2",
				PURL:      "pkg:generic/python@3.9.2",
				Locations: locations("python3.9"),
				Metadata: pkg.BinaryMetadata{
					Matches: []pkg.ClassifierMatch{
						match("python-binary", "python3.9"),
					},
				},
			},
		},
		{
			name:       "positive-python-binary-3.4-alpine",
			fixtureDir: "test-fixtures/classifiers/dynamic/python-binary-3.4-alpine",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.4.10",
				PURL:      "pkg:generic/python@3.4.10",
				Locations: locations("python3.4", "libpython3.4m.so.1.0"),
				Metadata: pkg.BinaryMetadata{
					Matches: []pkg.ClassifierMatch{
						match("python-binary", "python3.4"),
						match("python-binary", "libpython3.4m.so.1.0"),
						match("python-binary-lib", "libpython3.4m.so.1.0"),
					},
				},
			},
		},
		{
			name:       "positive-python-3.5-with-incorrect-match",
			fixtureDir: "test-fixtures/classifiers/positive/python-3.5-with-incorrect-match",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.5.3",
				PURL:      "pkg:generic/python@3.5.3",
				Locations: locations("python3.5"),
				Metadata:  metadata("python-binary"),
			},
		},
		{
			name:       "positive-python3.6",
			fixtureDir: "test-fixtures/classifiers/positive/python-binary-3.6",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.6.3",
				PURL:      "pkg:generic/python@3.6.3",
				Locations: locations("python3.6"),
				Metadata:  metadata("python-binary"),
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
				Locations: locations("dir/python3.8", "python3.8", "libpython3.8.so"),
				Metadata: pkg.BinaryMetadata{
					Matches: []pkg.ClassifierMatch{
						match("python-binary", "dir/python3.8"),
						match("python-binary", "python3.8"),
						match("python-binary-lib", "libpython3.8.so"),
					},
				},
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
		{
			name:       "positive-ruby-3.2.1",
			fixtureDir: "test-fixtures/classifiers/dynamic/ruby-library-3.2.1",
			expected: pkg.Package{
				Name:      "ruby",
				Version:   "3.2.1",
				Type:      "binary",
				PURL:      "pkg:generic/ruby@3.2.1",
				Locations: locations("ruby", "libruby.so.3.2.1"),
				Metadata: pkg.BinaryMetadata{
					Matches: []pkg.ClassifierMatch{
						match("ruby-binary", "ruby"),
						match("ruby-binary", "libruby.so.3.2.1"),
					},
				},
			},
		},
		{
			name:       "positive-ruby-2.7.7",
			fixtureDir: "test-fixtures/classifiers/dynamic/ruby-library-2.7.7",
			expected: pkg.Package{
				Name:      "ruby",
				Version:   "2.7.7p221",
				Type:      "binary",
				PURL:      "pkg:generic/ruby@2.7.7p221",
				Locations: locations("ruby", "libruby.so.2.7.7"),
				Metadata: pkg.BinaryMetadata{
					Matches: []pkg.ClassifierMatch{
						match("ruby-binary", "ruby"),
						match("ruby-binary", "libruby.so.2.7.7"),
					},
				},
			},
		},
		{
			name:       "positive-ruby-2.6.10",
			fixtureDir: "test-fixtures/classifiers/dynamic/ruby-library-2.6.10",
			expected: pkg.Package{
				Name:      "ruby",
				Version:   "2.6.10p210",
				Type:      "binary",
				PURL:      "pkg:generic/ruby@2.6.10p210",
				Locations: locations("ruby", "libruby.so.2.6.10"),
				Metadata: pkg.BinaryMetadata{
					Matches: []pkg.ClassifierMatch{
						match("ruby-binary", "ruby"),
						match("ruby-binary", "libruby.so.2.6.10"),
					},
				},
			},
		},
		{
			name:       "positive-ruby-1.9.3p551",
			fixtureDir: "test-fixtures/classifiers/positive/ruby-1.9.3p551",
			expected: pkg.Package{
				Name:      "ruby",
				Version:   "1.9.3p551",
				Type:      "binary",
				PURL:      "pkg:generic/ruby@1.9.3p551",
				Locations: locations("ruby"),
				Metadata:  metadata("ruby-binary"),
			},
		},
		{
			name:       "positive-consul-1.15.2",
			fixtureDir: "test-fixtures/classifiers/dynamic/consul-1.15.2",
			expected: pkg.Package{
				Name:      "consul",
				Version:   "1.15.2",
				Type:      "binary",
				PURL:      "pkg:golang/github.com/hashicorp/consul@1.15.2",
				Locations: locations("consul"),
				Metadata:  metadata("consul-binary"),
			},
		},
		{
			name:       "positive-nginx-1.25.1",
			fixtureDir: "test-fixtures/classifiers/positive/nginx-1.25.1",
			expected: pkg.Package{
				Name:      "nginx",
				Version:   "1.25.1",
				Type:      "binary",
				PURL:      "pkg:generic/nginx@1.25.1",
				Locations: locations("nginx"),
				Metadata:  metadata("nginx-binary"),
			},
		},
		{
			name:       "positive-nginx-openresty-1.21.4.2",
			fixtureDir: "test-fixtures/classifiers/positive/nginx-openresty-1.21.4.2",
			expected: pkg.Package{
				Name:      "nginx",
				Version:   "1.21.4",
				Type:      "binary",
				PURL:      "pkg:generic/nginx@1.21.4",
				Locations: locations("nginx"),
				Metadata:  metadata("nginx-binary"),
			},
		},
		{
			name:       "positive-bash-5.2.15",
			fixtureDir: "test-fixtures/classifiers/positive/bash-5.2.15",
			expected: pkg.Package{
				Name:      "bash",
				Version:   "5.2.15",
				Type:      "binary",
				PURL:      "pkg:generic/bash@5.2.15",
				Locations: locations("bash"),
				Metadata:  metadata("bash-binary"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewCataloger()

			src, err := source.NewFromDirectoryPath(test.fixtureDir)
			require.NoError(t, err)

			resolver, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			packages, _, err := c.Catalog(resolver)
			require.NoError(t, err)

			require.Len(t, packages, 1)

			assertPackagesAreEqual(t, test.expected, packages[0])
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
			src, err := source.NewFromStereoscopeImageObject(img, test.fixtureImage, nil)
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

	src, err := source.NewFromDirectoryPath("test-fixtures/classifiers/negative")
	assert.NoError(t, err)

	resolver, err := src.FileResolver(source.SquashedScope)
	assert.NoError(t, err)

	actualResults, _, err := c.Catalog(resolver)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(actualResults))
}

func locations(locations ...string) file.LocationSet {
	var locs []file.Location
	for _, s := range locations {
		locs = append(locs, file.NewLocation(s))
	}
	return file.NewLocationSet(locs...)
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
		Location: file.NewVirtualLocationFromCoordinates(
			file.Coordinates{
				RealPath: realPath,
			},
			virtualPath,
		),
	}
}

func assertPackagesAreEqual(t *testing.T, expected pkg.Package, p pkg.Package) {
	var failMessages []string
	expectedLocations := expected.Locations.ToSlice()
	gotLocations := p.Locations.ToSlice()

	if len(expectedLocations) != len(gotLocations) {
		failMessages = append(failMessages, "locations are not equal length")
	} else {
		for i, expectedLocation := range expectedLocations {
			gotLocation := gotLocations[i]
			if expectedLocation.RealPath != gotLocation.RealPath {
				failMessages = append(failMessages, fmt.Sprintf("locations do not match; expected: %v got: %v", expectedLocation.RealPath, gotLocation.RealPath))
			}
		}
	}

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

	if !matches {
		failMessages = append(failMessages, "classifier matches not equal")
	}
	if expected.Name != p.Name ||
		expected.Version != p.Version ||
		expected.PURL != p.PURL {
		failMessages = append(failMessages, "packages do not match")
	}

	if len(failMessages) > 0 {
		assert.Failf(t, strings.Join(failMessages, "; "), "diff: %s",
			cmp.Diff(expected, p,
				cmp.Transformer("Locations", func(l file.LocationSet) []file.Location {
					return l.ToSlice()
				}),
				cmpopts.IgnoreUnexported(pkg.Package{}, file.Location{}),
				cmpopts.IgnoreFields(pkg.Package{}, "CPEs", "FoundBy", "MetadataType", "Type"),
			))
	}
}

type panicyResolver struct {
	searchCalled bool
}

func (p *panicyResolver) FilesByExtension(_ ...string) ([]file.Location, error) {
	p.searchCalled = true
	return nil, errors.New("not implemented")
}

func (p *panicyResolver) FilesByBasename(_ ...string) ([]file.Location, error) {
	p.searchCalled = true
	return nil, errors.New("not implemented")
}

func (p *panicyResolver) FilesByBasenameGlob(_ ...string) ([]file.Location, error) {
	p.searchCalled = true
	return nil, errors.New("not implemented")
}

func (p *panicyResolver) FileContentsByLocation(_ file.Location) (io.ReadCloser, error) {
	p.searchCalled = true
	return nil, errors.New("not implemented")
}

func (p *panicyResolver) HasPath(_ string) bool {
	return true
}

func (p *panicyResolver) FilesByPath(_ ...string) ([]file.Location, error) {
	p.searchCalled = true
	return nil, errors.New("not implemented")
}

func (p *panicyResolver) FilesByGlob(_ ...string) ([]file.Location, error) {
	p.searchCalled = true
	return nil, errors.New("not implemented")
}

func (p *panicyResolver) FilesByMIMEType(_ ...string) ([]file.Location, error) {
	p.searchCalled = true
	return nil, errors.New("not implemented")
}

func (p *panicyResolver) RelativeFileByPath(_ file.Location, _ string) *file.Location {
	return nil
}

func (p *panicyResolver) AllLocations() <-chan file.Location {
	return nil
}

func (p *panicyResolver) FileMetadataByLocation(_ file.Location) (file.Metadata, error) {
	return file.Metadata{}, errors.New("not implemented")
}

var _ file.Resolver = (*panicyResolver)(nil)

func Test_Cataloger_ResilientToErrors(t *testing.T) {
	c := NewCataloger()

	resolver := &panicyResolver{}
	_, _, err := c.Catalog(resolver)
	assert.NoError(t, err)
	assert.True(t, resolver.searchCalled)
}
