package binary

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/stereoscope/pkg/imagetest"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/binary/test-fixtures/manager/testutil"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
	"github.com/anchore/syft/syft/source/stereoscopesource"
)

var mustUseOriginalBinaries = flag.Bool("must-use-original-binaries", false, "force the use of binaries for testing (instead of snippets)")

func Test_Cataloger_PositiveCases(t *testing.T) {
	tests := []struct {
		name string
		// logicalFixture is the logical path to the full binary or snippet. This is relative to the test-fixtures/classifiers/snippets
		// or test-fixtures/classifiers/bin directory . Snippets are searched for first, and if not found, then existing binaries are
		// used. If no binary or snippet is found the test will fail. If '-must-use-original-binaries' is used the only
		// full binaries are tested (no snippets), and if no binary is found the test will be skipped.
		logicalFixture string
		expected       pkg.Package
	}{
		{
			logicalFixture: "arangodb/3.11.8/linux-amd64",
			expected: pkg.Package{
				Name:      "arangodb",
				Version:   "3.11.8",
				Type:      "binary",
				PURL:      "pkg:generic/arangodb@3.11.8",
				Locations: locations("arangosh"),
				Metadata:  metadata("arangodb-binary"),
			},
		},
		{
			logicalFixture: "arangodb/3.12.0-2/linux-amd64",
			expected: pkg.Package{
				Name:      "arangodb",
				Version:   "3.12.0-2",
				Type:      "binary",
				PURL:      "pkg:generic/arangodb@3.12.0-2",
				Locations: locations("arangosh"),
				Metadata:  metadata("arangodb-binary"),
			},
		},
		{
			logicalFixture: "postgres/15beta4/linux-amd64",
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
			logicalFixture: "postgres/15.1/linux-amd64",
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
			logicalFixture: "postgres/9.6.24/linux-amd64",
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
			// TODO: find original binary...
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "postgres/9.5alpha1/linux-amd64",
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
			logicalFixture: "mysql/8.0.34/linux-amd64",
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
			logicalFixture: "mysql/8.0.37/linux-amd64",
			expected: pkg.Package{
				Name:      "mysql",
				Version:   "8.0.37",
				Type:      "binary",
				PURL:      "pkg:generic/mysql@8.0.37",
				Locations: locations("mysql"),
				Metadata:  metadata("mysql-binary"),
			},
		},
		{
			logicalFixture: "percona-server/8.0.35/linux-amd64",
			expected: pkg.Package{
				Name:      "percona-server",
				Version:   "8.0.35",
				Type:      "binary",
				PURL:      "pkg:generic/percona-server@8.0.35",
				Locations: locations("mysql"),
				Metadata:  metadata("mysql-binary"),
			},
		},
		{
			logicalFixture: "percona-xtradb-cluster/8.0.34/linux-amd64",
			expected: pkg.Package{
				Name:      "percona-xtradb-cluster",
				Version:   "8.0.34",
				Type:      "binary",
				PURL:      "pkg:generic/percona-xtradb-cluster@8.0.34",
				Locations: locations("mysql"),
				Metadata:  metadata("mysql-binary"),
			},
		},
		{
			logicalFixture: "percona-xtrabackup/8.0.35/linux-amd64",
			expected: pkg.Package{
				Name:      "percona-xtrabackup",
				Version:   "8.0.35",
				Type:      "binary",
				PURL:      "pkg:generic/percona-xtrabackup@8.0.35",
				Locations: locations("xtrabackup"),
				Metadata:  metadata("xtrabackup-binary"),
			},
		},
		{
			logicalFixture: "mysql/5.6.51/linux-amd64",
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
			logicalFixture: "mariadb/10.6.15/linux-amd64",
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
			logicalFixture: "traefik/1.7.34/linux-amd64",
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
			logicalFixture: "traefik/2.9.6/linux-amd64",
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
			logicalFixture: "traefik/2.10.7/linux-amd64",
			expected: pkg.Package{
				Name:      "traefik",
				Version:   "2.10.7",
				Type:      "binary",
				PURL:      "pkg:generic/traefik@2.10.7",
				Locations: locations("traefik"),
				Metadata:  metadata("traefik-binary"),
			},
		},
		{
			logicalFixture: "traefik/3.0.4/linux-riscv64",
			expected: pkg.Package{
				Name:      "traefik",
				Version:   "3.0.4",
				Type:      "binary",
				PURL:      "pkg:generic/traefik@3.0.4",
				Locations: locations("traefik"),
				Metadata:  metadata("traefik-binary"),
			},
		},
		{
			logicalFixture: "memcached/1.6.18/linux-amd64",
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
			logicalFixture: "httpd/2.4.54/linux-amd64",
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
			// TODO: find original binary...
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "php-cli/8.2.1/linux-amd64",
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
			// TODO: find original binary...
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "php-fpm/8.2.1/linux-amd64",
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
			// TODO: find original binary...
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "php-apache/8.2.1/linux-amd64",
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
			// TODO: original binary is different than whats in config.yaml
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "perl/5.12.5/linux-amd64",
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
			// TODO: original binary is different than whats in config.yaml
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "perl/5.20.0/linux-amd64",
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
			// TODO: original binary is different than whats in config.yaml
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "perl/5.37.8/linux-amd64",
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
			logicalFixture: "haproxy/1.5.14/linux-amd64",
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
			logicalFixture: "haproxy/1.8.22/linux-amd64",
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
			logicalFixture: "haproxy/2.0.0/linux-amd64",
			expected: pkg.Package{
				Name:      "haproxy",
				Version:   "2.0.0",
				Type:      "binary",
				PURL:      "pkg:generic/haproxy@2.0.0",
				Locations: locations("haproxy"),
				Metadata:  metadata("haproxy-binary"),
			},
		},
		{
			logicalFixture: "haproxy/2.7.3/linux-amd64",
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
			logicalFixture: "haproxy/3.1-dev0/linux-amd64",
			expected: pkg.Package{
				Name:      "haproxy",
				Version:   "3.1-dev0",
				Type:      "binary",
				PURL:      "pkg:generic/haproxy@3.1-dev0",
				Locations: locations("haproxy"),
				Metadata:  metadata("haproxy-binary"),
			},
		},
		{
			logicalFixture: "helm/3.11.1/linux-amd64",
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
			logicalFixture: "helm/3.10.3/linux-amd64",
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
			// note: dynamic (non-snippet) test case
			logicalFixture: "redis-server/2.8.23/linux-amd64",
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
			// note: dynamic (non-snippet) test case
			logicalFixture: "redis-server/4.0.11/linux-amd64",
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
			logicalFixture: "redis-server/5.0.0/linux-amd64",
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
			logicalFixture: "redis-server/6.0.16/linux-amd64",
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
			logicalFixture: "redis-server/7.0.0/linux-amd64",
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
			logicalFixture: "redis-server/7.0.14/linux-amd64",
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
			// note: dynamic (non-snippet) test case
			logicalFixture: "redis-server/7.2.3/linux-amd64",
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
			// note: dynamic (non-snippet) test case
			logicalFixture: "redis-server/7.2.3/linux-arm64",
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
			logicalFixture: "redis-server/7.2.5/linux-386",
			expected: pkg.Package{
				Name:      "redis",
				Version:   "7.2.5",
				Type:      "binary",
				PURL:      "pkg:generic/redis@7.2.5",
				Locations: locations("redis-server"),
				Metadata:  metadata("redis-binary"),
			},
		},
		{
			logicalFixture: "python-shared-lib/3.7.4/linux-amd64",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.7.4",
				PURL:      "pkg:generic/python@3.7.4",
				Locations: locations("libpython3.7m.so.1.0"),
				Metadata:  metadata("python-binary-lib"),
			},
		},

		{
			// note: dynamic (non-snippet) test case
			logicalFixture: "python-slim-shared-libs/3.11/linux-amd64",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.11.2",
				PURL:      "pkg:generic/python@3.11.2",
				Locations: locations("python3.11", "libpython3.11.so.1.0"),
				Metadata: pkg.BinarySignature{
					Matches: []pkg.ClassifierMatch{
						match("python-binary", "python3.11"),
						match("python-binary", "libpython3.11.so.1.0"),
						match("python-binary-lib", "libpython3.11.so.1.0"),
					},
				},
			},
		},
		{
			// note: dynamic (non-snippet) test case
			logicalFixture: "python-rhel-shared-libs/3.9/linux-amd64",
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
			// note: dynamic (non-snippet) test case
			logicalFixture: "python3.9/3.9.16/linux-amd64",
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
			// note: dynamic (non-snippet) test case
			logicalFixture: "python-alpine-shared-libs/3.4/linux-amd64",
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
			// TODO: find original binary...
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "python-with-incorrect-match/3.5.3/linux-amd64",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.5.3",
				PURL:      "pkg:generic/python@3.5.3",
				Locations: locations("python3.5"),
				Metadata:  metadata("python-binary"),
			},
		},
		{
			// TODO: find original binary...
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "python/3.6.3/linux-amd64",
			expected: pkg.Package{
				Name:      "python",
				Version:   "3.6.3",
				PURL:      "pkg:generic/python@3.6.3",
				Locations: locations("python3.6"),
				Metadata:  metadata("python-binary"),
			},
		},
		{
			// TODO: find original binary...
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "python-duplicates/3.8.16/linux-amd64",
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
		{
			logicalFixture: "pypy-shared-lib/7.3.14/linux-amd64",
			expected: pkg.Package{
				Name:      "pypy",
				Version:   "7.3.14",
				PURL:      "pkg:generic/pypy@7.3.14",
				Locations: locations("libpypy3.9-c.so"),
				Metadata:  metadata("pypy-binary-lib"),
			},
		},
		{
			logicalFixture: "go/1.21.3/linux-amd64",
			expected: pkg.Package{
				Name:      "go",
				Version:   "1.21.3",
				PURL:      "pkg:generic/go@1.21.3",
				Locations: locations("go"),
				Metadata:  metadata("go-binary"),
			},
		},
		{
			logicalFixture: "node/0.10.48/linux-amd64",
			expected: pkg.Package{
				Name:      "node",
				Version:   "0.10.48",
				PURL:      "pkg:generic/node@0.10.48",
				Locations: locations("node"),
				Metadata:  metadata("nodejs-binary"),
			},
		},
		{
			logicalFixture: "node/0.12.18/linux-amd64",
			expected: pkg.Package{
				Name:      "node",
				Version:   "0.12.18",
				PURL:      "pkg:generic/node@0.12.18",
				Locations: locations("node"),
				Metadata:  metadata("nodejs-binary"),
			},
		},
		{
			logicalFixture: "node/4.9.1/linux-amd64",
			expected: pkg.Package{
				Name:      "node",
				Version:   "4.9.1",
				PURL:      "pkg:generic/node@4.9.1",
				Locations: locations("node"),
				Metadata:  metadata("nodejs-binary"),
			},
		},
		{
			logicalFixture: "node/19.2.0/linux-amd64",
			expected: pkg.Package{
				Name:      "node",
				Version:   "19.2.0",
				PURL:      "pkg:generic/node@19.2.0",
				Locations: locations("node"),
				Metadata:  metadata("nodejs-binary"),
			},
		},
		{
			// TODO: find original binary...
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "go-version-hint/1.15/any",
			expected: pkg.Package{
				Name:      "go",
				Version:   "1.15",
				PURL:      "pkg:generic/go@1.15",
				Locations: locations("VERSION"),
				Metadata:  metadata("go-binary-hint"),
			},
		},
		{
			// note: this is testing BUSYBOX which is typically through a link to "[" (in this case a symlink but in
			// practice this is often a hard link).
			logicalFixture: `busybox/1.36.1/linux-amd64`,
			expected: pkg.Package{
				Name:      "busybox",
				Version:   "1.36.1",
				PURL:      "pkg:generic/busybox@1.36.1",
				Locations: locations("["), // note: busybox is a link to [
				Metadata:  metadata("busybox-binary", "[", "busybox"),
			},
		},
		{
			logicalFixture: `util-linux/2.37.4/linux-amd64`,
			expected: pkg.Package{
				Name:      "util-linux",
				Version:   "2.37.4",
				PURL:      "pkg:generic/util-linux@2.37.4",
				Locations: locations("getopt"),
				Metadata:  metadata("util-linux-binary"),
			},
		},
		{
			logicalFixture: "java-jre-openjdk/1.8.0_352-b08/linux-amd64",
			expected: pkg.Package{
				Name:      "java/jre",
				Version:   "1.8.0_352-b08",
				Type:      "binary",
				PURL:      "pkg:generic/java/jre@1.8.0_352-b08",
				Locations: locations("java"),
				Metadata:  metadata("java-binary-openjdk", "java"),
			},
		},
		{
			logicalFixture: "java-jre-openjdk/11.0.17/linux-amd64",
			expected: pkg.Package{
				Name:      "java/jre",
				Version:   "11.0.17+8-LTS",
				Type:      "binary",
				PURL:      "pkg:generic/java/jre@11.0.17%2B8-LTS",
				Locations: locations("java"),
				Metadata:  metadata("java-binary-openjdk", "java"),
			},
		},
		{
			logicalFixture: "java-jre-openjdk-eclipse/11.0.22/linux-amd64",
			expected: pkg.Package{
				Name:      "java/jre",
				Version:   "11.0.22+7",
				Type:      "binary",
				PURL:      "pkg:generic/java/jre@11.0.22%2B7",
				Locations: locations("java"),
				Metadata:  metadata("java-binary-openjdk", "java"),
			},
		},
		{
			logicalFixture: "java-jre-openjdk-arm64-eclipse/11.0.22/linux-arm64",
			expected: pkg.Package{
				Name:      "java/jre",
				Version:   "11.0.22+7",
				Type:      "binary",
				PURL:      "pkg:generic/java/jre@11.0.22%2B7",
				Locations: locations("java"),
				Metadata:  metadata("java-binary-openjdk", "java"),
			},
		},
		{
			logicalFixture: "java-graal-openjdk/17.0.3+7-jvmci-22.1-b06/linux-amd64",
			expected: pkg.Package{
				Name:      "java/graalvm",
				Version:   "17.0.3+7-jvmci-22.1-b06",
				Type:      "binary",
				PURL:      "pkg:generic/java/graalvm@17.0.3%2B7-jvmci-22.1-b06",
				Locations: locations("java"),
				Metadata:  metadata("java-binary-graalvm", "java"),
			},
		},
		{
			// TODO: find original binary...
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "java-jre-oracle/19.0.1/linux-amd64",
			expected: pkg.Package{
				Name:      "java/jre",
				Version:   "19.0.1+10-21",
				Type:      "binary",
				PURL:      "pkg:generic/java/jre@19.0.1%2B10-21",
				Locations: locations("java"),
				Metadata:  metadata("java-binary-oracle", "java"),
			},
		},
		{
			// TODO: find original binary...
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "java-jre-oracle/19.0.1/darwin",
			expected: pkg.Package{
				Name:      "java/jre",
				Version:   "19.0.1+10-21",
				Type:      "binary",
				PURL:      "pkg:generic/java/jre@19.0.1%2B10-21",
				Locations: locations("java"),
				Metadata:  metadata("java-binary-oracle", "java"),
			},
		},
		{
			logicalFixture: "java-jre-ibm/1.8.0_391/linux-amd64",
			expected: pkg.Package{
				Name:      "java/jre",
				Version:   "1.8.0-foreman_2023_10_12_13_27-b00",
				Type:      "binary",
				PURL:      "pkg:generic/java/jre@1.8.0-foreman_2023_10_12_13_27-b00",
				Locations: locations("java"),
				Metadata:  metadata("java-binary-ibm", "java"),
			},
		},
		{
			logicalFixture: "java-jdk-openjdk/21.0.2+13-LTS/linux-amd64",
			expected: pkg.Package{
				Name:      "java/jdk",
				Version:   "21.0.2+13-LTS",
				Type:      "binary",
				PURL:      "pkg:generic/java/jdk@21.0.2%2B13-LTS",
				Locations: locations("jdb"),
				Metadata:  metadata("java-binary-jdk", "java"),
			},
		},
		{
			logicalFixture: "rust-libstd/1.50.0/linux-amd64",
			expected: pkg.Package{
				Name:      "rust",
				Version:   "1.50.0",
				Type:      "binary",
				PURL:      "pkg:generic/rust@1.50.0",
				Locations: locations("libstd-6f77337c1826707d.so"),
				Metadata:  metadata("rust-standard-library-linux"),
			},
		},
		{
			// TODO: find original binary...
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "rust-libstd/1.50.0/darwin",
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
			// TODO: find original binary...
			// note: cannot find the original binary, using a custom snippet based on the original snippet in the repo
			logicalFixture: "rust-libstd/1.67.1/darwin",
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
			logicalFixture: "rust-libstd-musl/1.67.1/linux-amd64",
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
			logicalFixture: "rust-libstd/1.67.1/linux-amd64",
			expected: pkg.Package{
				Name:      "rust",
				Version:   "1.67.1",
				Type:      "binary",
				PURL:      "pkg:generic/rust@1.67.1",
				Locations: locations("libstd-c6192dd4c4d410ac.so"),
				Metadata:  metadata("rust-standard-library-linux"),
			},
		},
		{
			// note: dynamic (non-snippet) test case

			name:           "positive-ruby-3.2.1",
			logicalFixture: "ruby-bullseye-shared-libs/3.2.1/linux-amd64",
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
			// note: dynamic (non-snippet) test case
			name:           "positive-ruby-3.4.0-dev",
			logicalFixture: "ruby-shared-libs/3.4.0-dev/linux-amd64",
			expected: pkg.Package{
				Name:      "ruby",
				Version:   "3.4.0dev",
				Type:      "binary",
				PURL:      "pkg:generic/ruby@3.4.0dev",
				Locations: locations("ruby", "libruby.so.3.4.0"),
				Metadata: pkg.BinarySignature{
					Matches: []pkg.ClassifierMatch{
						match("ruby-binary", "ruby"),
						match("ruby-binary", "libruby.so.3.4.0"),
					},
				},
			},
		},
		{
			// note: dynamic (non-snippet) test case
			name:           "positive-ruby-3.4.0-preview1",
			logicalFixture: "ruby-shared-libs/3.4.0-preview1/linux-amd64",
			expected: pkg.Package{
				Name:      "ruby",
				Version:   "3.4.0preview1",
				Type:      "binary",
				PURL:      "pkg:generic/ruby@3.4.0preview1",
				Locations: locations("ruby", "libruby.so.3.4.0"),
				Metadata: pkg.BinarySignature{
					Matches: []pkg.ClassifierMatch{
						match("ruby-binary", "ruby"),
						match("ruby-binary", "libruby.so.3.4.0"),
					},
				},
			},
		},
		{
			// note: dynamic (non-snippet) test case
			name:           "positive-ruby-3.3.0-rc1",
			logicalFixture: "ruby-shared-libs/3.3.0-rc1/linux-amd64",
			expected: pkg.Package{
				Name:      "ruby",
				Version:   "3.3.0rc1",
				Type:      "binary",
				PURL:      "pkg:generic/ruby@3.3.0rc1",
				Locations: locations("ruby", "libruby.so.3.3.0"),
				Metadata: pkg.BinarySignature{
					Matches: []pkg.ClassifierMatch{
						match("ruby-binary", "ruby"),
						match("ruby-binary", "libruby.so.3.3.0"),
					},
				},
			},
		},
		{
			// note: dynamic (non-snippet) test case
			logicalFixture: "ruby-bullseye-shared-libs/2.7.7/linux-amd64",
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
			// note: dynamic (non-snippet) test case
			logicalFixture: "ruby-shared-libs/2.6.10/linux-amd64",
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
			logicalFixture: "ruby/1.9.3p551/linux-amd64",
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
			logicalFixture: "consul/1.15.2/linux-amd64",
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
			logicalFixture: "erlang/25.3.2.6/linux-amd64",
			expected: pkg.Package{
				Name:      "erlang",
				Version:   "25.3.2.6",
				Type:      "binary",
				PURL:      "pkg:generic/erlang@25.3.2.6",
				Locations: locations("erlexec"),
				Metadata:  metadata("erlang-binary"),
			},
		},
		{
			logicalFixture: "erlang/26.2.0.0/linux-amd64",
			expected: pkg.Package{
				Name:      "erlang",
				Version:   "26.2",
				Type:      "binary",
				PURL:      "pkg:generic/erlang@26.2",
				Locations: locations("erlexec"),
				Metadata:  metadata("erlang-binary"),
			},
		},
		{
			logicalFixture: "erlang/26.2.4/linux-amd64",
			expected: pkg.Package{
				Name:      "erlang",
				Version:   "26.2.4",
				Type:      "binary",
				PURL:      "pkg:generic/erlang@26.2.4",
				Locations: locations("liberts_internal.a"),
				Metadata:  metadata("erlang-library"),
			},
		},
		{
			logicalFixture: "erlang/27.0/linux-amd64",
			expected: pkg.Package{
				Name:      "erlang",
				Version:   "27.0",
				Type:      "binary",
				PURL:      "pkg:generic/erlang@27.0",
				Locations: locations("beam.smp"),
				Metadata:  metadata("erlang-alpine-binary"),
			},
		},
		{
			logicalFixture: "swipl/9.3.8/linux-amd64",
			expected: pkg.Package{
				Name:      "swipl",
				Version:   "9.3.8",
				Type:      "binary",
				PURL:      "pkg:generic/swipl@9.3.8",
				Locations: locations("swipl"),
				Metadata:  metadata("swipl-binary"),
			},
		},
		{
			logicalFixture: "dart/2.12.4/linux-amd64",
			expected: pkg.Package{
				Name:      "dart",
				Version:   "2.12.4",
				Type:      "binary",
				PURL:      "pkg:generic/dart@2.12.4",
				Locations: locations("dart"),
				Metadata:  metadata("dart-binary"),
			},
		},
		{
			logicalFixture: "dart/3.0.0/linux-arm",
			expected: pkg.Package{
				Name:      "dart",
				Version:   "3.0.0",
				Type:      "binary",
				PURL:      "pkg:generic/dart@3.0.0",
				Locations: locations("dart"),
				Metadata:  metadata("dart-binary"),
			},
		},
		{
			logicalFixture: "dart/3.5.2/linux-amd64",
			expected: pkg.Package{
				Name:      "dart",
				Version:   "3.5.2",
				Type:      "binary",
				PURL:      "pkg:generic/dart@3.5.2",
				Locations: locations("dart"),
				Metadata:  metadata("dart-binary"),
			},
		},
		{
			logicalFixture: "dart/3.6.0-216.1.beta/linux-amd64",
			expected: pkg.Package{
				Name:      "dart",
				Version:   "3.6.0-216.1.beta",
				Type:      "binary",
				PURL:      "pkg:generic/dart@3.6.0-216.1.beta",
				Locations: locations("dart"),
				Metadata:  metadata("dart-binary"),
			},
		},
		{
			logicalFixture: "haskell-ghc/9.6.5/linux-amd64",
			expected: pkg.Package{
				Name:      "haskell/ghc",
				Version:   "9.6.5",
				Type:      "binary",
				PURL:      "pkg:generic/haskell/ghc@9.6.5",
				Locations: locations("ghc-9.6.5"),
				Metadata:  metadata("haskell-ghc-binary"),
			},
		},
		{
			logicalFixture: "haskell-cabal/3.10.3.0/linux-amd64",
			expected: pkg.Package{
				Name:      "haskell/cabal",
				Version:   "3.10.3.0",
				Type:      "binary",
				PURL:      "pkg:generic/haskell/cabal@3.10.3.0",
				Locations: locations("cabal"),
				Metadata:  metadata("haskell-cabal-binary"),
			},
		},
		{
			logicalFixture: "nginx/1.25.1/linux-amd64",
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
			logicalFixture: "nginx-openresty/1.21.4.3/linux-amd64",
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
			logicalFixture: "bash/5.1.16/linux-amd64",
			expected: pkg.Package{
				Name:      "bash",
				Version:   "5.1.16",
				Type:      "binary",
				PURL:      "pkg:generic/bash@5.1.16",
				Locations: locations("bash"),
				Metadata:  metadata("bash-binary"),
			},
		},
		{
			logicalFixture: "openssl/3.1.4/linux-amd64",
			expected: pkg.Package{
				Name:      "openssl",
				Version:   "3.1.4",
				Type:      "binary",
				PURL:      "pkg:generic/openssl@3.1.4",
				Locations: locations("openssl"),
				Metadata:  metadata("openssl-binary"),
			},
		},
		{
			logicalFixture: "openssl/1.1.1w/linux-arm64",
			expected: pkg.Package{
				Name:      "openssl",
				Version:   "1.1.1w",
				Type:      "binary",
				PURL:      "pkg:generic/openssl@1.1.1w",
				Locations: locations("openssl"),
				Metadata:  metadata("openssl-binary"),
			},
		},
		{
			logicalFixture: "gcc/12.3.0/linux-amd64",
			expected: pkg.Package{
				Name:      "gcc",
				Version:   "12.3.0",
				Type:      "binary",
				PURL:      "pkg:generic/gcc@12.3.0",
				Locations: locations("gcc"),
				Metadata:  metadata("gcc-binary"),
			},
		},
		{
			logicalFixture: "fluent-bit/3.0.2/linux-amd64",
			expected: pkg.Package{
				Name:      "fluent-bit",
				Version:   "3.0.2",
				Type:      "binary",
				PURL:      "pkg:github/fluent/fluent-bit@3.0.2",
				Locations: locations("fluent-bit"),
				Metadata:  metadata("fluent-bit-binary"),
			},
		},
		{
			logicalFixture: "fluent-bit/2.2.1/linux-arm64",
			expected: pkg.Package{
				Name:      "fluent-bit",
				Version:   "2.2.1",
				Type:      "binary",
				PURL:      "pkg:github/fluent/fluent-bit@2.2.1",
				Locations: locations("fluent-bit"),
				Metadata:  metadata("fluent-bit-binary"),
			},
		},
		{
			logicalFixture: "wp/2.9.0/linux-amd64",
			expected: pkg.Package{
				Name:      "wp-cli",
				Version:   "2.9.0",
				Type:      "binary",
				PURL:      "pkg:generic/wp-cli@2.9.0",
				Locations: locations("wp"),
				Metadata:  metadata("wordpress-cli-binary"),
			},
		},
		{
			logicalFixture: "lighttpd/1.4.76/linux-amd64",
			expected: pkg.Package{
				Name:      "lighttpd",
				Version:   "1.4.76",
				Type:      "binary",
				PURL:      "pkg:generic/lighttpd@1.4.76",
				Locations: locations("lighttpd"),
				Metadata:  metadata("lighttpd-binary"),
			},
		},
		{
			logicalFixture: "proftpd/1.3.8b/linux-amd64",
			expected: pkg.Package{
				Name:      "proftpd",
				Version:   "1.3.8b",
				Type:      "binary",
				PURL:      "pkg:generic/proftpd@1.3.8b",
				Locations: locations("proftpd"),
				Metadata:  metadata("proftpd-binary"),
			},
		},
		{
			logicalFixture: "zstd/1.5.6/linux-amd64",
			expected: pkg.Package{
				Name:      "zstd",
				Version:   "1.5.6",
				Type:      "binary",
				PURL:      "pkg:generic/zstd@1.5.6",
				Locations: locations("zstd"),
				Metadata:  metadata("zstd-binary"),
			},
		},
		{
			logicalFixture: "zstd/1.5.6/linux-amd64",
			expected: pkg.Package{
				Name:      "zstd",
				Version:   "1.5.6",
				Type:      "binary",
				PURL:      "pkg:generic/zstd@1.5.6",
				Locations: locations("zstd"),
				Metadata:  metadata("zstd-binary"),
			},
		},
		{
			logicalFixture: "xz/5.6.2/linux-amd64",
			expected: pkg.Package{
				Name:      "xz",
				Version:   "5.6.2",
				Type:      "binary",
				PURL:      "pkg:generic/xz@5.6.2",
				Locations: locations("xz"),
				Metadata:  metadata("xz-binary"),
			},
		},
		{
			logicalFixture: "gzip/1.12/linux-amd64",
			expected: pkg.Package{
				Name:      "gzip",
				Version:   "1.12",
				Type:      "binary",
				PURL:      "pkg:generic/gzip@1.12",
				Locations: locations("gzip"),
				Metadata:  metadata("gzip-binary"),
			},
		},
		{
			logicalFixture: "sqlcipher/4.5.5/linux-amd64",
			expected: pkg.Package{
				Name:      "sqlcipher",
				Version:   "4.5.5",
				Type:      "binary",
				PURL:      "pkg:generic/sqlcipher@4.5.5",
				Locations: locations("sqlcipher"),
				Metadata:  metadata("sqlcipher-binary"),
			},
		},
		{
			logicalFixture: "jq/1.7.1/linux-amd64",
			expected: pkg.Package{
				Name:      "jq",
				Version:   "1.7.1",
				Type:      "binary",
				PURL:      "pkg:generic/jq@1.7.1",
				Locations: locations("jq"),
				Metadata:  metadata("jq-binary"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.logicalFixture, func(t *testing.T) {
			c := NewClassifierCataloger(DefaultClassifierCatalogerConfig())

			// logicalFixture is the logical path to the full binary or snippet. This is relative to the test-fixtures/classifiers/snippets
			// or test-fixtures/classifiers/bin directory . Snippets are searched for first, and if not found, then existing binaries are
			// used. If no binary or snippet is found the test will fail. If '-must-use-original-binaries' is used the only
			// full binaries are tested (no snippets), and if no binary is found the test will be skipped.
			path := testutil.SnippetOrBinary(t, test.logicalFixture, *mustUseOriginalBinaries)

			src, err := directorysource.NewFromPath(path)
			require.NoError(t, err)

			resolver, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			packages, _, err := c.Catalog(context.Background(), resolver)
			require.NoError(t, err)

			require.Len(t, packages, 1, "mismatched package count")

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
				PURL:      "pkg:generic/busybox@1.35.0",
				Locations: locations("/bin/["),
				Metadata:  metadata("busybox-binary", "/bin/[", "/bin/busybox"),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewClassifierCataloger(DefaultClassifierCatalogerConfig())

			img := imagetest.GetFixtureImage(t, "docker-archive", test.fixtureImage)
			src := stereoscopesource.New(img, stereoscopesource.ImageConfig{
				Reference: test.fixtureImage,
			})

			resolver, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			packages, _, err := c.Catalog(context.Background(), resolver)
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
	c := NewClassifierCataloger(DefaultClassifierCatalogerConfig())

	src, err := directorysource.NewFromPath("test-fixtures/classifiers/negative")
	assert.NoError(t, err)

	resolver, err := src.FileResolver(source.SquashedScope)
	assert.NoError(t, err)

	actualResults, _, err := c.Catalog(context.Background(), resolver)
	assert.NoError(t, err)
	assert.Equal(t, 0, len(actualResults))
}

func Test_Cataloger_CustomClassifiers(t *testing.T) {
	defaultClassifers := DefaultClassifiers()

	golangExpected := pkg.Package{
		Name:      "go",
		Version:   "1.14",
		PURL:      "pkg:generic/go@1.14",
		Locations: locations("go"),
		Metadata:  metadata("go-binary"),
	}
	customExpected := pkg.Package{
		Name:      "foo",
		Version:   "1.2.3",
		PURL:      "pkg:generic/foo@1.2.3",
		Locations: locations("foo"),
		Metadata:  metadata("foo-binary"),
	}
	fooClassifier := Classifier{
		Class:    "foo-binary",
		FileGlob: "**/foo",
		EvidenceMatcher: FileContentsVersionMatcher(
			`(?m)foobar\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		Package: "foo",
		PURL:    mustPURL("pkg:generic/foo@version"),
		CPEs:    singleCPE("cpe:2.3:a:foo:foo:*:*:*:*:*:*:*:*"),
	}

	tests := []struct {
		name       string
		config     ClassifierCatalogerConfig
		fixtureDir string
		expected   *pkg.Package
	}{
		{
			name: "empty-negative",
			config: ClassifierCatalogerConfig{
				Classifiers: []Classifier{},
			},
			fixtureDir: "test-fixtures/custom/go-1.14",
			expected:   nil,
		},
		{
			name: "default-positive",
			config: ClassifierCatalogerConfig{
				Classifiers: defaultClassifers,
			},
			fixtureDir: "test-fixtures/custom/go-1.14",
			expected:   &golangExpected,
		},
		{
			name: "nodefault-negative",
			config: ClassifierCatalogerConfig{
				Classifiers: []Classifier{fooClassifier},
			},
			fixtureDir: "test-fixtures/custom/go-1.14",
			expected:   nil,
		},
		{
			name: "default-extended-positive",
			config: ClassifierCatalogerConfig{
				Classifiers: append(
					append([]Classifier{}, defaultClassifers...),
					fooClassifier,
				),
			},
			fixtureDir: "test-fixtures/custom/go-1.14",
			expected:   &golangExpected,
		},
		{
			name: "default-custom-negative",
			config: ClassifierCatalogerConfig{

				Classifiers: append(
					append([]Classifier{}, defaultClassifers...),
					Classifier{
						Class:           "foo-binary",
						FileGlob:        "**/foo",
						EvidenceMatcher: FileContentsVersionMatcher(`(?m)not there`),
						Package:         "foo",
						PURL:            mustPURL("pkg:generic/foo@version"),
						CPEs:            singleCPE("cpe:2.3:a:foo:foo:*:*:*:*:*:*:*:*"),
					},
				),
			},
			fixtureDir: "test-fixtures/custom/extra",
			expected:   nil,
		},
		{
			name: "default-cutsom-positive",
			config: ClassifierCatalogerConfig{
				Classifiers: append(
					append([]Classifier{}, defaultClassifers...),
					fooClassifier,
				),
			},
			fixtureDir: "test-fixtures/custom/extra",
			expected:   &customExpected,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewClassifierCataloger(test.config)

			src, err := directorysource.NewFromPath(test.fixtureDir)
			require.NoError(t, err)

			resolver, err := src.FileResolver(source.SquashedScope)
			require.NoError(t, err)

			packages, _, err := c.Catalog(context.Background(), resolver)
			require.NoError(t, err)

			if test.expected == nil {
				assert.Equal(t, 0, len(packages))
			} else {
				require.Len(t, packages, 1)

				assertPackagesAreEqual(t, *test.expected, packages[0])
			}
		})
	}
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
				cmpopts.IgnoreUnexported(pkg.Package{}, file.LocationData{}),
				cmpopts.IgnoreFields(pkg.Package{}, "CPEs", "FoundBy", "Type", "Locations", "Licenses"),
			),
		)
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

func (p *panicyResolver) AllLocations(_ context.Context) <-chan file.Location {
	return nil
}

func (p *panicyResolver) FileMetadataByLocation(_ file.Location) (file.Metadata, error) {
	return file.Metadata{}, errors.New("not implemented")
}

var _ file.Resolver = (*panicyResolver)(nil)

func Test_Cataloger_ResilientToErrors(t *testing.T) {
	c := NewClassifierCataloger(DefaultClassifierCatalogerConfig())

	resolver := &panicyResolver{}
	_, _, err := c.Catalog(context.Background(), resolver)
	assert.Nil(t, err) // non-coordinate-based FindBy* errors are now logged and not returned
	assert.True(t, resolver.searchCalled)
}

func TestCatalogerConfig_MarshalJSON(t *testing.T) {

	tests := []struct {
		name    string
		cfg     ClassifierCatalogerConfig
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "only show names of classes",
			cfg: ClassifierCatalogerConfig{
				Classifiers: []Classifier{
					{
						Class:           "class",
						FileGlob:        "glob",
						EvidenceMatcher: FileContentsVersionMatcher(".thing"),
						Package:         "pkg",
						PURL: packageurl.PackageURL{
							Type:       "type",
							Namespace:  "namespace",
							Name:       "name",
							Version:    "version",
							Qualifiers: nil,
							Subpath:    "subpath",
						},
						CPEs: []cpe.CPE{cpe.Must("cpe:2.3:a:some:app:*:*:*:*:*:*:*:*", cpe.GeneratedSource)},
					},
				},
			},
			want: `["class"]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			got, err := tt.cfg.MarshalJSON()
			if !tt.wantErr(t, err) {
				return
			}
			assert.Equal(t, tt.want, string(got))
		})
	}
}
