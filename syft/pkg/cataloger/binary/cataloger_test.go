package binary

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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

func Test_Cataloger_DefaultClassifiers_DynamicCases(t *testing.T) {
	tests := []struct {
		name       string
		fixtureDir string
		expected   pkg.Package
	}{
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
			name:       "positive-python-3.11.2-from-shared-lib",
			fixtureDir: "test-fixtures/classifiers/dynamic/python-binary-shared-lib-3.11",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.11.2",
				PURL:      "pkg:generic/python@3.11.2",
				Locations: locations("python3", "libpython3.11.so.1.0"),
				Metadata: pkg.BinarySignature{
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
				Metadata: pkg.BinarySignature{
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
				Metadata: pkg.BinarySignature{
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
				Metadata: pkg.BinarySignature{
					Matches: []pkg.ClassifierMatch{
						match("python-binary", "python3.4"),
						match("python-binary", "libpython3.4m.so.1.0"),
						match("python-binary-lib", "libpython3.4m.so.1.0"),
					},
				},
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
				Metadata: pkg.BinarySignature{
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
				Metadata: pkg.BinarySignature{
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
				Metadata: pkg.BinarySignature{
					Matches: []pkg.ClassifierMatch{
						match("ruby-binary", "ruby"),
						match("ruby-binary", "libruby.so.2.6.10"),
					},
				},
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

func Test_Cataloger_DefaultClassifiers_PositiveCaseContents(t *testing.T) {
	tests := []struct {
		name       string
		fixtureDir string
		contents   []byte
		fileGlob   string
		expected   pkg.Package
	}{
		{
			name: "positive-postgresql-15beta4",
			// note [NUL] prefix is important for the EvidenceMatcher in this case
			contents: []byte("\u0000PostgreSQL 15beta4\n"),
			fileGlob: "postgres",
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
			name:     "positive-postgresql-15.1",
			contents: []byte("\u0000PostgreSQL 15.1\n"),
			fileGlob: "postgres",
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
			name:     "positive-postgresql-9.6.24",
			contents: []byte("\u0000PostgreSQL 9.6.24\n"),
			fileGlob: "postgres",
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
			name:     "positive-postgresql-9.5alpha1",
			contents: []byte("\u0000PostgreSQL 9.5alpha1\n"),
			fileGlob: "postgres",
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
			name:     "positive-mysql-8.0.34",
			contents: []byte(" is already loaded\u0000../../mysql-8.0.34/sql-common/client_plugin.cc"),
			fileGlob: "mysql",
			expected: pkg.Package{
				Name:      "mysql",
				Version:   "8.0.34",
				Type:      "binary",
				PURL:      "pkg:generic/mysql@8.0.34",
				Locations: locations("mysql"),
				Metadata:  metadata("mysql-binary"),
			},
		},
		{
			name:     "positive-mysql-5.6.51",
			contents: []byte("-backup-restorer-mysql-5.6/mysql-5.6.51/client/completion_hash.cc\u0000/var/vcap/data/compile/database-ba\n"),
			fileGlob: "mysql",
			expected: pkg.Package{
				Name:      "mysql",
				Version:   "5.6.51",
				Type:      "binary",
				PURL:      "pkg:generic/mysql@5.6.51",
				Locations: locations("mysql"),
				Metadata:  metadata("mysql-binary"),
			},
		},
		{
			name:     "positive-mariadb-10.6.15",
			contents: []byte(")\u0000Linux\u000010.6.15-MariaDB\u0000readline\u0000x86_64\u0000\n"),
			fileGlob: "mariadb",
			expected: pkg.Package{
				Name:      "mariadb",
				Version:   "10.6.15",
				Type:      "binary",
				PURL:      "pkg:generic/mariadb@10.6.15",
				Locations: locations("mariadb"),
				Metadata:  metadata("mariadb-binary"),
			},
		},
		{
			name:     "positive-traefik-2.9.6",
			contents: []byte("\u00002.9.6\u0000\n"),
			fileGlob: "traefik",
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
			name:     "positive-traefik-1.7.34",
			contents: []byte("\u0000v1.7.34\u0000\n"),
			fileGlob: "traefik",
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
			name:     "positive-memcached-1.6.18",
			contents: []byte("memcached 1.6.18\nudp-port\nmemcached 1.6.18\nFailed to allocate memory\nVERSION 1.6.18\nquit\n"),
			fileGlob: "memcached",
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
			name:     "positive-httpd-2.4.54",
			contents: []byte("<Directory \"\nmailto:\nApache/2.4.54\n Server at \nApache/2.4.54 (Unix)\nApache\nApache/2.4\nApache/2\n<VirtualHost\n<Limit\n"),
			fileGlob: "httpd",
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
			name:     "positive-php-cli-8.2.1",
			contents: []byte("[null]  X-Powered-By: PHP/8.2.1\nindex pointer\nPHP_VERSION\n"),
			fileGlob: "php",
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
			name:     "positive-php-fpm-8.2.1",
			contents: []byte("[null]  Script:  X-Powered-By: PHP/8.2.1\nindex pointer\nPHP_VERSION\n"),
			fileGlob: "php-fpm",
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
			name:     "positive-php-apache-8.2.1",
			contents: []byte("[null]  X-Powered-By: PHP/8.2.1\nindex pointer\nPHP_VERSION\n"),
			fileGlob: "libphp.so",
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
			name:     "positive-perl-5.12.5",
			contents: []byte(`/usr/local/lib/perl5/5.12.5-e/dev/fd/Can't open)`),
			fileGlob: "perl",
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
			name:     "positive-perl-5.20.0",
			contents: []byte(`/usr/local/lib/perl5/5.20.0 /dev/null:`),
			fileGlob: "perl",
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
			name:     "positive-perl-5.37.8",
			contents: []byte(`/usr/local/lib/perl5/5.37.8 /dev/null:`),
			fileGlob: "perl",
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
			name:     "positive-haproxy-1.5.14",
			contents: []byte("HA-Proxy version 1.5.14 2015/07/02Copyright 2000-2015 Willy Tarreau <willy@haproxy.org>\n"),
			fileGlob: "haproxy",
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
			name:     "positive-haproxy-1.8.22",
			contents: []byte("\u0000HA-Proxy version 1.8.22 2019/10/25\u0000Copyright 2000-2019 Willy Tarreau <willy@haproxy.org>\n"),
			fileGlob: "haproxy",
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
			name:     "positive-haproxy-2.7.3",
			contents: []byte("XZ\u0000\u0000 version 2.7.3-1065b10, released 2023/02/14u0000\u0000\u00002.7.3-1065b10HAProxy version follows\u0000\u0000\n"),
			fileGlob: "haproxy",
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
			name: "positive-redis-2.8.23",
			// note the extraction after payload and the \u000 is important for this case and finding 2.8.23
			contents: []byte("pl: %5u, pls: %2u, payload %5u} \u000000000000\u0000\u0000\u0000\u0000\u0000\u0000\u00002.8.231640342e135b-1465416213000000000"),
			fileGlob: "redis-server",
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
			name:     "positive-redis-4.0.11",
			contents: []byte("\tpayload %5u\n\u0000ziplist.c\u00004.0.11841ce7054bd9-1542359302000000000\u0000"),
			fileGlob: "redis-server",
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
			name:     "positive-redis-5.0.0",
			contents: []byte("\tpayload %5u\n\u0000ziplist.c\u0000prevlen\u00005.0.05ca5019de136-1539906480000000000\u0000"),
			fileGlob: "redis-server",
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
			name:     "positive-redis-6.0.16",
			contents: []byte("\tpayload %5u\n\u000000000000\u0000%llx\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u00006.0.16f823c11b1f9e-1671626578000000000\u0000networking.c\n"),
			fileGlob: "redis-server",
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
			contents:   []byte("\tpayload %5u\n0000\u0000\u00007.0.0e11381fbd8bd-1653733480000000000\u0000CACHING (YES|NO)\n"),
			fileGlob:   "redis-server",
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
			name:     "positive-redis-7.0.14",
			contents: []byte("\tpayload %5u\n\u0000\u0000\u0000\u0000\u0000\u0000ziplistGet(p, &value, &vlen, &vlval)\u0000\u00007.0.14buildkitsandbox-1698800572000000000\u0000\n"),
			fileGlob: "redis-server",
			expected: pkg.Package{
				Name:      "redis",
				Version:   "7.0.14",
				Type:      "binary",
				PURL:      "pkg:generic/redis@7.0.14",
				Locations: locations("redis-server"),
				Metadata:  metadata("redis-binary"),
			},
		},
		{
			name:     "positive-redis-7.2.3-amd64",
			contents: []byte("\u00007.2.3707d15b3058f-1698842949000000000\u0000\u0000\u0000zipEntrySafe(zl, zlbytes, p, &e, 0)\tpayload %5u\n"),
			fileGlob: "redis-server",
			expected: pkg.Package{
				Name:      "redis",
				Version:   "7.2.3",
				Type:      "binary",
				PURL:      "pkg:generic/redis@7.2.3",
				Locations: locations("redis-server"),
				Metadata:  metadata("redis-binary"),
			},
		},
		{
			name:     "positive-libpython3.7.so",
			contents: []byte("r\u0000python3.9\u0000PYTHONIOENCODING\u00003.7.4\u0000<prefix>/lib/pythonX.X\u0000Python %s\n\u0000\n"),
			fileGlob: "libpython3.7.so",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.7.4",
				PURL:      "pkg:generic/python@3.7.4",
				Locations: locations("libpython3.7.so"),
				Metadata:  metadata("python-binary-lib"),
			},
		},

		{
			name:       "positive-python-3.5-with-incorrect-match",
			contents:   []byte("\u0000305\u0000path\u0000path_importer_cache\u0000must be %.50s, not %.50s\u00003.5.3\u0000%.80s (%.80s) %.\n"),
			fileGlob:   "python3.5",
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
			name:     "positive-python3.6",
			contents: []byte("r\u0000python3.9\u0000PYTHONIOENCODING\u00003.6.3\u0000<prefix>/lib/pythonX.X\u0000Python %s\n"),
			fileGlob: "python3.6",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.6.3",
				PURL:      "pkg:generic/python@3.6.3",
				Locations: locations("python3.6"),
				Metadata:  metadata("python-binary"),
			},
		},

		{
			name: "positive-go",
			// Note the \x00 is important for this case, as it is a null byte that is used to terminate the string
			// this is expected for a positive match on the Golang executable
			contents: []byte(strings.Join([]string{`"go1.1"`, "go1.2", "go1.14\x00"}, "\n")),
			fileGlob: "go",
			expected: pkg.Package{
				Name:      "go",
				Version:   "1.14",
				PURL:      "pkg:generic/go@1.14",
				Locations: locations("go"),
				Metadata:  metadata("go-binary"),
			},
		},
		{
			name:     "positive-node",
			contents: []byte("# this should match node 19.2.1\nnode.js/v19.2.1\n"),
			fileGlob: "node",
			expected: pkg.Package{
				Name:      "node",
				Version:   "19.2.1",
				PURL:      "pkg:generic/node@19.2.1",
				Locations: locations("node"),
				Metadata:  metadata("nodejs-binary"),
			},
		},
		{
			name:     "positive-go-hint",
			contents: []byte("go1.15-beta2\n"),
			fileGlob: "VERSION",
			expected: pkg.Package{
				Name:      "go",
				Version:   "1.15",
				PURL:      "pkg:generic/go@1.15",
				Locations: locations("VERSION"),
				Metadata:  metadata("go-binary-hint"),
			},
		},

		{
			name:     "positive-java-openjdk",
			contents: []byte("\u0000\u0000\u0001\u0000\u0002\u0000openjdk\u0000java\u00001.8\u00001.8.0_352-b08\u0000\u0000\u0001\n"),
			fileGlob: "java",
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
			name:     "positive-java-openjdk-lts",
			contents: []byte("# java LTS pattern\nJDK_JAVA_OPTIONS\u0000_JAVA_LAUNCHER_DEBUG\u0000NOTE: Picked up %s: %s\u0000openjdk\u0000java\u00000.0\u000011.0.17+8-LTS\u0000-J-ms8m\u0000\u0001\u001B\u0003;\n"),
			fileGlob: "java",
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
			name:     "positive-java-oracle",
			contents: []byte("#this should be an oracle java binary\nwith: \u0000java\u00000.0\u000019.0.1+10-21\u0000\nand 18.0.2 has nothing to do with the version\n"),
			fileGlob: "java",
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
			name:     "positive-java-oracle-macos",
			contents: []byte("#oracle macos\nis different: \u000019.0.1+10-21\u00000.0\u0000java\u0000\nthis should not be 17.2.2\n"),
			fileGlob: "java",
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
			name:     "positive-java-ibm",
			contents: []byte("# this is an ibm java\n\u0001\u0000\u0002\u0000java\u00001.8\u0000\u0000\u0000\u00001.8.0-foreman_2022_09_22_15_30-b00\u0000\u0000\u0000\u0000\u0000\u0000\u0001\u001B\u0003;4\u0000\u0000\u0000\u0005\u0000\ntype of file 1.9.0 1.8.99\n"),
			fileGlob: "java",
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
			name:     "positive-rust-1.50.0-macos",
			contents: []byte("rust\u0000\u0000\u0000\u0005\u0000X¥g#\u0001\n\uF8FFÜc 1.50.0 (cb75ad5db 2021-02-10)\u0004coreÖ∫¡°é¿»üé\u0001\u0000\u0002\u0011-59ed52fd3946b1c5\u0011compiler_builtins"),
			fileGlob: "libstd-f6f9eec1635e636a.dylib",
			expected: pkg.Package{
				Name:      "rust",
				Version:   "1.50.0",
				Type:      "binary",
				PURL:      "pkg:generic/rust@1.50.0",
				Locations: locations("libstd-f6f9eec1635e636a.dylib"),
				Metadata:  metadata("rust-standard-library-macos"),
			},
		},
		{
			name:     "positive-rust-1.67.1-macos",
			contents: []byte("rust\u0000\u0000\u0000\u0006\u0000\u0089°·#\u0001\nðec 1.67.1 (d5a82bbd2 2023-02-07)Á\u0002á\u0003\u009AØ\u0098\u0089\u0080ïß\u0097»\u0001\u0000\u0002\u0011-33fcb3a02520939aÁ\n"),
			fileGlob: "libstd-16f2b65e77054c42.dylib",
			expected: pkg.Package{
				Name:      "rust",
				Version:   "1.67.1",
				Type:      "binary",
				PURL:      "pkg:generic/rust@1.67.1",
				Locations: locations("libstd-16f2b65e77054c42.dylib"),
				Metadata:  metadata("rust-standard-library-macos"),
			},
		},
		{
			name:     "positive-rust-1.67.1-linux",
			contents: []byte("obj_musl\u0000GNU AS 2.33.1\u0000clang LLVM (rustc version 1.67.1 (d5a82bbd2 2023-02-07))\u0000library/std/src/lib.rs/@/std.d836545c-cgu.0\n"),
			fileGlob: "libstd-86aefecbddda356d.so",
			expected: pkg.Package{
				Name:      "rust",
				Version:   "1.67.1",
				Type:      "binary",
				PURL:      "pkg:generic/rust@1.67.1",
				Locations: locations("libstd-86aefecbddda356d.so"),
				Metadata:  metadata("rust-standard-library-linux"),
			},
		},
		{
			name:     "positive-ruby-1.9.3p551",
			contents: []byte("ruby 1.9.3p551 (2014-11-13 revision 48407) [x86_64-linux]\n"),
			fileGlob: "ruby",
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
			name:     "positive-nginx-1.25.1",
			contents: []byte("\u0000\u0000nginx version: nginx/1.25.1\n"),
			fileGlob: "nginx",
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
			name:     "positive-nginx-openresty-1.21.4.2",
			contents: []byte("\u0000\u0000nginx version: openresty/1.21.4.2\n"),
			fileGlob: "nginx",
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
			name:     "positive-bash-5.2.15",
			contents: []byte("@(#)Bash version 5.2.15(1) release GNU\n"),
			fileGlob: "bash",
			expected: pkg.Package{
				Name:      "bash",
				Version:   "5.2.15",
				Type:      "binary",
				PURL:      "pkg:generic/bash@5.2.15",
				Locations: locations("bash"),
				Metadata:  metadata("bash-binary"),
			},
		},
		{
			name:     "positive-openssl-3.1.4",
			contents: []byte("\u0000\u0000N/A\u0000\u0000\u0000\u0000\u0000OpenSSL 3.1.4 24 Oct 2023\u0000\u0000\n"),
			fileGlob: "openssl",
			expected: pkg.Package{
				Name:      "openssl",
				Version:   "3.1.4",
				Type:      "binary",
				PURL:      "pkg:generic/openssl@3.1.4",
				Locations: locations("openssl"),
				Metadata:  metadata("openssl-binary"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir, cleanup, err := newFixtureFromBytes(test.contents, test.name, test.fileGlob)
			require.NoError(t, err)
			defer cleanup()
			c := NewCataloger()
			src, err := source.NewFromDirectoryPath(dir)
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

func Test_Cataloger_DefaultClassifiers_PositiveComplexCase(t *testing.T) {
	tests := []struct {
		name       string
		fixtureDir string
		expected   pkg.Package
	}{
		{
			name:       "positive-python-duplicates regression",
			fixtureDir: "test-fixtures/classifiers/python-duplicates",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.8.16",
				Type:      "binary",
				PURL:      "pkg:generic/python@3.8.16",
				Locations: locations("dir/python3.8", "python3.8", "libpython3.8.so"),
				Metadata: pkg.BinarySignature{
					Matches: []pkg.ClassifierMatch{
						match("python-binary", "dir/python3.8"),
						match("python-binary", "python3.8"),
						match("python-binary-lib", "libpython3.8.so"),
					},
				},
			},
		},
	}

	for _, test := range tests {
		c := NewCataloger()

		src, err := source.NewFromDirectoryPath(test.fixtureDir)
		require.NoError(t, err)

		resolver, err := src.FileResolver(source.SquashedScope)
		require.NoError(t, err)

		packages, _, err := c.Catalog(resolver)
		require.NoError(t, err)

		require.Len(t, packages, 1)

		assertPackagesAreEqual(t, test.expected, packages[0])
	}
}

func newFixtureFromBytes(contents []byte, testName, fileGlob string) (string, func(), error) {
	tempDir, err := os.MkdirTemp("", testName)
	if err != nil {
		return "", nil, err
	}

	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	err = os.WriteFile(filepath.Join(tempDir, fileGlob), contents, 0644)
	if err != nil {
		return "", cleanup, err
	}

	return tempDir, cleanup, nil

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
func metadata(classifier string, paths ...string) pkg.BinarySignature {
	return pkg.BinarySignature{
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

	m1 := expected.Metadata.(pkg.BinarySignature).Matches
	m2 := p.Metadata.(pkg.BinarySignature).Matches
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
			if m1.Location.AccessPath != "" && m1.Location.AccessPath != m2.Location.AccessPath {
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
