package binary

import (
	"github.com/anchore/syft/syft/cpe"
)

//nolint:funlen
func DefaultClassifiers() []Classifier {
	return []Classifier{
		{
			Class:    "python-binary",
			FileGlob: "**/python*",
			EvidenceMatcher: evidenceMatchers(
				// try to find version information from libpython shared libraries
				sharedLibraryLookup(
					`^libpython[0-9]+(?:\.[0-9]+)+[a-z]?\.so.*$`,
					libpythonMatcher),
				// check for version information in the binary
				fileNameTemplateVersionMatcher(
					`(?:.*/|^)python(?P<version>[0-9]+(?:\.[0-9]+)+)$`,
					pythonVersionTemplate),
			),
			Package: "python",
			PURL:    mustPURL("pkg:generic/python@version"),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:python_software_foundation:python:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
				cpe.Must("cpe:2.3:a:python:python:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
			},
		},
		{
			Class:           "python-binary-lib",
			FileGlob:        "**/libpython*.so*",
			EvidenceMatcher: libpythonMatcher,
			Package:         "python",
			PURL:            mustPURL("pkg:generic/python@version"),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:python_software_foundation:python:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
				cpe.Must("cpe:2.3:a:python:python:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
			},
		},
		{
			Class:    "pypy-binary-lib",
			FileGlob: "**/libpypy*.so*",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)\[PyPy (?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "pypy",
			PURL:    mustPURL("pkg:generic/pypy@version"),
		},
		{
			Class:    "go-binary",
			FileGlob: "**/go",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)?)\x00`),
			Package: "go",
			PURL:    mustPURL("pkg:generic/go@version"),
			CPEs:    singleCPE("cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "julia-binary",
			FileGlob: "**/libjulia-internal.so",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)__init__\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00verify`),
			Package: "julia",
			PURL:    mustPURL("pkg:generic/julia@version"),
			CPEs:    singleCPE("cpe:2.3:a:julialang:julia:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "helm",
			FileGlob: "**/helm",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)\x00v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`),
			Package: "helm",
			PURL:    mustPURL("pkg:golang/helm.sh/helm@version"),
			CPEs:    singleCPE("cpe:2.3:a:helm:helm:*:*:*:*:*:*:*"),
		},
		{
			Class:    "redis-binary",
			FileGlob: "**/redis-server",
			EvidenceMatcher: evidenceMatchers(
				FileContentsVersionMatcher(`(?s)payload %5.*?(?P<version>\d.\d\.\d\d*)[a-z0-9]{12,15}-[0-9]{19}`),
				FileContentsVersionMatcher(`(?s)\x00(?P<version>\d.\d\.\d\d*)[a-z0-9]{12}-[0-9]{19}\x00.*?payload %5`),
			),
			Package: "redis",
			PURL:    mustPURL("pkg:generic/redis@version"),
			CPEs:    singleCPE("cpe:2.3:a:redislabs:redis:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "java-binary-openjdk",
			FileGlob: "**/java",
			EvidenceMatcher: matchExcluding(
				evidenceMatchers(
					FileContentsVersionMatcher(
						// [NUL]openjdk[NUL]java[NUL]0.0[NUL]11.0.17+8-LTS[NUL]
						// [NUL]openjdk[NUL]java[NUL]1.8[NUL]1.8.0_352-b08[NUL]
						`(?m)\x00openjdk\x00java\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>[0-9]+[^\x00]+)\x00`),
					FileContentsVersionMatcher(
						// arm64 versions: [NUL]0.0[NUL][NUL][NUL][NUL][NUL]11.0.22+7[NUL][NUL][NUL][NUL][NUL][NUL][NUL]openjdk[NUL]java[NUL]
						`(?m)\x00(?P<release>[0-9]+[.0-9]*)\x00+(?P<version>[0-9]+[^\x00]+)\x00+openjdk\x00java`),
				),
				// don't match graalvm
				"-jvmci-",
			),
			Package: "java/jre",
			PURL:    mustPURL("pkg:generic/java/jre@version"),
			// TODO the updates might need to be part of the CPE Attributes, like: 1.8.0:update152
			CPEs: singleCPE("cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "java-binary-ibm",
			FileGlob: "**/java",
			EvidenceMatcher: FileContentsVersionMatcher(
				// [NUL]java[NUL]1.8[NUL][NUL][NUL][NUL]1.8.0-foreman_2022_09_22_15_30-b00[NUL]
				`(?m)\x00java\x00(?P<release>[0-9]+[.0-9]+)\x00{4}(?P<version>[0-9]+[-._a-zA-Z0-9]+)\x00`),
			Package: "java/jre",
			PURL:    mustPURL("pkg:generic/java/jre@version"),
			CPEs:    singleCPE("cpe:2.3:a:ibm:java:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "java-binary-oracle",
			FileGlob: "**/java",
			EvidenceMatcher: matchExcluding(
				FileContentsVersionMatcher(
					// [NUL]19.0.1+10-21[NUL]
					`(?m)\x00(?P<version>[0-9]+[.0-9]+[+][-0-9]+)\x00`),
				// don't match openjdk
				`\x00openjdk\x00`,
			),
			Package: "java/jre",
			PURL:    mustPURL("pkg:generic/java/jre@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:jre:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "java-binary-graalvm",
			FileGlob: "**/java",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)\x00(?P<version>[0-9]+[.0-9]+[.0-9]+\+[0-9]+-jvmci-[0-9]+[.0-9]+-b[0-9]+)\x00`),
			Package: "java/graalvm",
			PURL:    mustPURL("pkg:generic/java/graalvm@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:graalvm:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "java-binary-jdk",
			FileGlob: "**/jdb",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\+[0-9]+)?([-._a-zA-Z0-9]+)?)\x00`),
			Package: "java/jdk",
			PURL:    mustPURL("pkg:generic/java/jdk@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "nodejs-binary",
			FileGlob: "**/node",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)node\.js\/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "node",
			PURL:    mustPURL("pkg:generic/node@version"),
			CPEs:    singleCPE("cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "go-binary-hint",
			FileGlob: "**/VERSION",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)?)`),
			Package: "go",
			PURL:    mustPURL("pkg:generic/go@version"),
		},
		{
			Class:    "busybox-binary",
			FileGlob: "**/busybox",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)BusyBox\s+v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "busybox",
			PURL:    mustPURL("pkg:generic/busybox@version"),
			CPEs:    singleCPE("cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "haproxy-binary",
			FileGlob: "**/haproxy",
			EvidenceMatcher: evidenceMatchers(
				FileContentsVersionMatcher(`(?m)HA-Proxy version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
				FileContentsVersionMatcher(`(?m)(?P<version>[0-9]+\.[0-9]+\.[0-9]+)-[0-9a-zA-Z]{7}.+HAProxy version`),
			),
			Package: "haproxy",
			PURL:    mustPURL("pkg:generic/haproxy@version"),
			CPEs:    singleCPE("cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "perl-binary",
			FileGlob: "**/perl",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)\/usr\/local\/lib\/perl\d\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "perl",
			PURL:    mustPURL("pkg:generic/perl@version"),
			CPEs:    singleCPE("cpe:2.3:a:perl:perl:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "php-cli-binary",
			FileGlob: "**/php*",
			EvidenceMatcher: fileNameTemplateVersionMatcher(
				`(.*/|^)php[0-9]*$`,
				`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`),
			Package: "php-cli",
			PURL:    mustPURL("pkg:generic/php-cli@version"),
			CPEs:    singleCPE("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "php-fpm-binary",
			FileGlob: "**/php-fpm*",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`),
			Package: "php-fpm",
			PURL:    mustPURL("pkg:generic/php-fpm@version"),
			CPEs:    singleCPE("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "php-apache-binary",
			FileGlob: "**/libphp*.so",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`),
			Package: "libphp",
			PURL:    mustPURL("pkg:generic/php@version"),
			CPEs:    singleCPE("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "php-composer-binary",
			FileGlob: "**/composer*",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)'pretty_version'\s*=>\s*'(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)'`),
			Package: "composer",
			PURL:    mustPURL("pkg:generic/composer@version"),
			CPEs:    singleCPE("cpe:2.3:a:getcomposer:composer:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "httpd-binary",
			FileGlob: "**/httpd",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)Apache\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "httpd",
			PURL:    mustPURL("pkg:generic/httpd@version"),
			CPEs:    singleCPE("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "memcached-binary",
			FileGlob: "**/memcached",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)memcached\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "memcached",
			PURL:    mustPURL("pkg:generic/memcached@version"),
			CPEs:    singleCPE("cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "traefik-binary",
			FileGlob: "**/traefik",
			EvidenceMatcher: FileContentsVersionMatcher(
				// [NUL]v1.7.34[NUL]
				// [NUL]2.9.6[NUL]
				`(?m)(\x00|\x{FFFD})v?(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00`),
			Package: "traefik",
			PURL:    mustPURL("pkg:generic/traefik@version"),
			CPEs:    singleCPE("cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "arangodb-binary",
			FileGlob: "**/arangosh",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)ArangoDB\s\x00*(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\s\[linux\]`),
			Package: "arangodb",
			PURL:    mustPURL("pkg:generic/arangodb@version"),
			CPEs:    singleCPE("cpe:2.3:a:arangodb:arangodb:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "postgresql-binary",
			FileGlob: "**/postgres",
			EvidenceMatcher: FileContentsVersionMatcher(
				// [NUL]PostgreSQL 15beta4
				// [NUL]PostgreSQL 15.1
				// [NUL]PostgreSQL 9.6.24
				// ?PostgreSQL 9.5alpha1
				`(?m)(\x00|\?)PostgreSQL (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
			Package: "postgresql",
			PURL:    mustPURL("pkg:generic/postgresql@version"),
			CPEs:    singleCPE("cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "mysql-binary",
			FileGlob: "**/mysql",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m).*/mysql-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
			Package: "mysql",
			PURL:    mustPURL("pkg:generic/mysql@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "mysql-binary",
			FileGlob: "**/mysql",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m).*/percona-server-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
			Package: "percona-server",
			PURL:    mustPURL("pkg:generic/percona-server@version"),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
				cpe.Must("cpe:2.3:a:percona:percona_server:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
			},
		},
		{
			Class:    "mysql-binary",
			FileGlob: "**/mysql",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m).*/Percona-XtraDB-Cluster-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
			Package: "percona-xtradb-cluster",
			PURL:    mustPURL("pkg:generic/percona-xtradb-cluster@version"),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
				cpe.Must("cpe:2.3:a:percona:percona_server:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
				cpe.Must("cpe:2.3:a:percona:xtradb_cluster:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
			},
		},
		{
			Class:    "xtrabackup-binary",
			FileGlob: "**/xtrabackup",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m).*/percona-xtrabackup-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
			Package: "percona-xtrabackup",
			PURL:    mustPURL("pkg:generic/percona-xtrabackup@version"),
			CPEs:    singleCPE("cpe:2.3:a:percona:xtrabackup:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "mariadb-binary",
			FileGlob: "**/mariadb",
			EvidenceMatcher: FileContentsVersionMatcher(
				// 10.6.15-MariaDB
				`(?m)(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)-MariaDB`),
			Package: "mariadb",
			PURL:    mustPURL("pkg:generic/mariadb@version"),
		},
		{
			Class:    "rust-standard-library-linux",
			FileGlob: "**/libstd-????????????????.so",
			EvidenceMatcher: FileContentsVersionMatcher(
				// clang LLVM (rustc version 1.48.0 (7eac88abb 2020-11-16))
				`(?m)(\x00)clang LLVM \(rustc version (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)) \(\w+ \d{4}\-\d{2}\-\d{2}\)`),
			Package: "rust",
			PURL:    mustPURL("pkg:generic/rust@version"),
			CPEs:    singleCPE("cpe:2.3:a:rust-lang:rust:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "rust-standard-library-macos",
			FileGlob: "**/libstd-????????????????.dylib",
			EvidenceMatcher: FileContentsVersionMatcher(
				// c 1.48.0 (7eac88abb 2020-11-16)
				`(?m)c (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)) \(\w+ \d{4}\-\d{2}\-\d{2}\)`),
			Package: "rust",
			PURL:    mustPURL("pkg:generic/rust@version"),
			CPEs:    singleCPE("cpe:2.3:a:rust-lang:rust:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "ruby-binary",
			FileGlob: "**/ruby",
			EvidenceMatcher: evidenceMatchers(
				rubyMatcher,
				sharedLibraryLookup(
					// try to find version information from libruby shared libraries
					`^libruby\.so.*$`,
					rubyMatcher),
			),
			Package: "ruby",
			PURL:    mustPURL("pkg:generic/ruby@version"),
			CPEs:    singleCPE("cpe:2.3:a:ruby-lang:ruby:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "erlang-binary",
			FileGlob: "**/erlexec",
			EvidenceMatcher: evidenceMatchers(
				FileContentsVersionMatcher(
					// <artificial>[NUL]/usr/src/otp_src_25.3.2.6/erts/
					`(?m)/src/otp_src_(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/`,
				),
				FileContentsVersionMatcher(
					// <artificial>[NUL]/usr/local/src/otp-25.3.2.7/erts/
					`(?m)/usr/local/src/otp-(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/`,
				),
			),
			Package: "erlang",
			PURL:    mustPURL("pkg:generic/erlang@version"),
			CPEs:    singleCPE("cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "erlang-library",
			FileGlob: "**/liberts_internal.a",
			EvidenceMatcher: evidenceMatchers(
				FileContentsVersionMatcher(
					// <artificial>[NUL]/usr/src/otp_src_25.3.2.6/erts/
					`(?m)/src/otp_src_(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/`,
				),
				FileContentsVersionMatcher(
					// <artificial>[NUL]/usr/local/src/otp-25.3.2.7/erts/
					`(?m)/usr/local/src/otp-(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/`,
				),
			),
			Package: "erlang",
			PURL:    mustPURL("pkg:generic/erlang@version"),
			CPEs:    singleCPE("cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "consul-binary",
			FileGlob: "**/consul",
			EvidenceMatcher: FileContentsVersionMatcher(
				// NOTE: This is brittle and may not work for past or future versions
				`CONSUL_VERSION: (?P<version>\d+\.\d+\.\d+)`,
			),
			Package: "consul",
			PURL:    mustPURL("pkg:golang/github.com/hashicorp/consul@version"),
			CPEs:    singleCPE("cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "nginx-binary",
			FileGlob: "**/nginx",
			EvidenceMatcher: FileContentsVersionMatcher(
				// [NUL]nginx version: nginx/1.25.1 - fetches '1.25.1'
				// [NUL]nginx version: openresty/1.21.4.1 - fetches '1.21.4' as this is the nginx version part
				`(?m)(\x00|\?)nginx version: [^\/]+\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:\+\d+)?(?:-\d+)?)`,
			),
			Package: "nginx",
			PURL:    mustPURL("pkg:generic/nginx@version"),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
				cpe.Must("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", cpe.GeneratedSource),
			},
		},
		{
			Class:    "bash-binary",
			FileGlob: "**/bash",
			EvidenceMatcher: FileContentsVersionMatcher(
				// @(#)Bash version 5.2.15(1) release GNU
				// @(#)Bash version 5.2.0(1) alpha GNU
				// @(#)Bash version 5.2.0(1) beta GNU
				// @(#)Bash version 5.2.0(1) rc4 GNU
				`(?m)@\(#\)Bash version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\([0-9]\) [a-z0-9]+ GNU`,
			),
			Package: "bash",
			PURL:    mustPURL("pkg:generic/bash@version"),
			CPEs:    singleCPE("cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "openssl-binary",
			FileGlob: "**/openssl",
			EvidenceMatcher: FileContentsVersionMatcher(
				// [NUL]OpenSSL 3.1.4'
				// [NUL]OpenSSL 1.1.1w'
				`\x00OpenSSL (?P<version>[0-9]+\.[0-9]+\.[0-9]+([a-z]|-alpha[0-9]|-beta[0-9]|-rc[0-9])?)`,
			),
			Package: "openssl",
			PURL:    mustPURL("pkg:generic/openssl@version"),
			CPEs:    singleCPE("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "gcc-binary",
			FileGlob: "**/gcc",
			EvidenceMatcher: FileContentsVersionMatcher(
				// GCC: \(GNU\)  12.3.0'
				`GCC: \(GNU\) (?P<version>[0-9]+\.[0-9]+\.[0-9]+)`,
			),
			Package: "gcc",
			PURL:    mustPURL("pkg:generic/gcc@version"),
			CPEs:    singleCPE("cpe:2.3:a:gnu:gcc:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "fluent-bit-binary",
			FileGlob: "**/fluent-bit",
			EvidenceMatcher: FileContentsVersionMatcher(
				// [NUL]3.0.2[NUL]%sFluent Bit
				// [NUL]2.2.3[NUL]Fluent Bit
				// [NUL]2.2.1[NUL][NUL][NUL]Fluent Bit
				`\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00[^\d]*Fluent`,
			),
			Package: "fluent-bit",
			PURL:    mustPURL("pkg:github/fluent/fluent-bit@version"),
			CPEs:    singleCPE("cpe:2.3:a:treasuredata:fluent_bit:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "wordpress-cli-binary",
			FileGlob: "**/wp",
			EvidenceMatcher: FileContentsVersionMatcher(
				// wp-cli/wp-cli 2.9.0'
				`(?m)wp-cli/wp-cli (?P<version>[0-9]+\.[0-9]+\.[0-9]+)`,
			),
			Package: "wp-cli",
			PURL:    mustPURL("pkg:generic/wp-cli@version"),
			CPEs:    singleCPE("cpe:2.3:a:wp-cli:wp-cli:*:*:*:*:*:*:*:*"),
		},
	}
}

// in both binaries and shared libraries, the version pattern is [NUL]3.11.2[NUL]
var pythonVersionTemplate = `(?m)\x00(?P<version>{{ .version }}[-._a-zA-Z0-9]*)\x00`

var libpythonMatcher = fileNameTemplateVersionMatcher(
	`(?:.*/|^)libpython(?P<version>[0-9]+(?:\.[0-9]+)+)[a-z]?\.so.*$`,
	pythonVersionTemplate,
)

var rubyMatcher = FileContentsVersionMatcher(
	// ruby 3.2.1 (2023-02-08 revision 31819e82c8) [x86_64-linux]
	// ruby 2.7.7p221 (2022-11-24 revision 168ec2b1e5) [x86_64-linux]
	`(?m)ruby (?P<version>[0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?) `)
