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
				cpe.Must("cpe:2.3:a:python_software_foundation:python:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				cpe.Must("cpe:2.3:a:python:python:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
			},
		},
		{
			Class:           "python-binary-lib",
			FileGlob:        "**/libpython*.so*",
			EvidenceMatcher: libpythonMatcher,
			Package:         "python",
			PURL:            mustPURL("pkg:generic/python@version"),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:python_software_foundation:python:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				cpe.Must("cpe:2.3:a:python:python:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
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
			CPEs:    singleCPE("cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "julia-binary",
			FileGlob: "**/libjulia-internal.so",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)__init__\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00verify`),
			Package: "julia",
			PURL:    mustPURL("pkg:generic/julia@version"),
			CPEs:    singleCPE("cpe:2.3:a:julialang:julia:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "helm",
			FileGlob: "**/helm",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)\x00v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`),
			Package: "helm",
			PURL:    mustPURL("pkg:golang/helm.sh/helm@version"),
			CPEs:    singleCPE("cpe:2.3:a:helm:helm:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "redis-binary",
			FileGlob: "**/redis-server",
			EvidenceMatcher: evidenceMatchers(
				// matches most recent versions of redis (~v7), e.g. "7.0.14buildkitsandbox-1702957741000000000"
				FileContentsVersionMatcher(`[^\d](?P<version>\d+.\d+\.\d+)buildkitsandbox-\d+`),
				// matches against older versions of redis (~v3 - v6), e.g. "4.0.11841ce7054bd9-1542359302000000000"
				FileContentsVersionMatcher(`[^\d](?P<version>[0-9]+\.[0-9]+\.[0-9]+)\w{12}-\d+`),
				// matches against older versions of redis (~v2), e.g. "Server started, Redis version 2.8.23"
				FileContentsVersionMatcher(`Redis version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			),
			Package: "redis",
			PURL:    mustPURL("pkg:generic/redis@version"),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:redislabs:redis:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				cpe.Must("cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
			},
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
			CPEs: singleCPE("cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "java-binary-ibm",
			FileGlob: "**/java",
			EvidenceMatcher: FileContentsVersionMatcher(
				// [NUL]java[NUL]1.8[NUL][NUL][NUL][NUL]1.8.0-foreman_2022_09_22_15_30-b00[NUL]
				`(?m)\x00java\x00(?P<release>[0-9]+[.0-9]+)\x00{4}(?P<version>[0-9]+[-._a-zA-Z0-9]+)\x00`),
			Package: "java/jre",
			PURL:    mustPURL("pkg:generic/java/jre@version"),
			CPEs:    singleCPE("cpe:2.3:a:ibm:java:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
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
			CPEs:    singleCPE("cpe:2.3:a:oracle:jre:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "java-binary-graalvm",
			FileGlob: "**/java",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)\x00(?P<version>[0-9]+[.0-9]+[.0-9]+\+[0-9]+-jvmci-[0-9]+[.0-9]+-b[0-9]+)\x00`),
			Package: "java/graalvm",
			PURL:    mustPURL("pkg:generic/java/graalvm@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:graalvm:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "java-binary-jdk",
			FileGlob: "**/jdb",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\+[0-9]+)?([-._a-zA-Z0-9]+)?)\x00`),
			Package: "java/jdk",
			PURL:    mustPURL("pkg:generic/java/jdk@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:jdk:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "nodejs-binary",
			FileGlob: "**/node",
			EvidenceMatcher: evidenceMatchers(
				// [NUL]node v0.10.48[NUL]
				// [NUL]v0.12.18[NUL]
				// [NUL]v4.9.1[NUL]
				// node.js/v22.9.0
				FileContentsVersionMatcher(`(?m)\x00(node )?v(?P<version>(0|4|5|6)\.[0-9]+\.[0-9]+)\x00`),
				FileContentsVersionMatcher(`(?m)node\.js\/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			),
			Package: "node",
			PURL:    mustPURL("pkg:generic/node@version"),
			CPEs:    singleCPE("cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "go-binary-hint",
			FileGlob: "**/VERSION",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)?)`),
			Package: "go",
			PURL:    mustPURL("pkg:generic/go@version"),
			CPEs:    singleCPE("cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "busybox-binary",
			FileGlob: "**/busybox",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)BusyBox\s+v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "busybox",
			PURL:    mustPURL("pkg:generic/busybox@version"),
			CPEs:    singleCPE("cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "util-linux-binary",
			FileGlob: "**/getopt",
			EvidenceMatcher: FileContentsVersionMatcher(
				`\x00util-linux\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`),
			Package: "util-linux",
			PURL:    mustPURL("pkg:generic/util-linux@version"),
			CPEs:    singleCPE("cpe:2.3:a:kernel:util-linux:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "haproxy-binary",
			FileGlob: "**/haproxy",
			EvidenceMatcher: evidenceMatchers(
				FileContentsVersionMatcher(`(?m)version (?P<version>[0-9]+\.[0-9]+(\.|-dev|-rc)[0-9]+)(-[a-z0-9]{7})?, released 20`),
				FileContentsVersionMatcher(`(?m)HA-Proxy version (?P<version>[0-9]+\.[0-9]+(\.|-dev)[0-9]+)`),
				FileContentsVersionMatcher(`(?m)(?P<version>[0-9]+\.[0-9]+(\.|-dev)[0-9]+)-[0-9a-zA-Z]{7}.+HAProxy version`),
			),
			Package: "haproxy",
			PURL:    mustPURL("pkg:generic/haproxy@version"),
			CPEs:    singleCPE("cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "perl-binary",
			FileGlob: "**/perl",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)\/usr\/local\/lib\/perl\d\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "perl",
			PURL:    mustPURL("pkg:generic/perl@version"),
			CPEs:    singleCPE("cpe:2.3:a:perl:perl:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "php-cli-binary",
			FileGlob: "**/php*",
			EvidenceMatcher: fileNameTemplateVersionMatcher(
				`(.*/|^)php[0-9]*$`,
				`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`),
			Package: "php-cli",
			PURL:    mustPURL("pkg:generic/php-cli@version"),
			CPEs:    singleCPE("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "php-fpm-binary",
			FileGlob: "**/php-fpm*",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`),
			Package: "php-fpm",
			PURL:    mustPURL("pkg:generic/php-fpm@version"),
			CPEs:    singleCPE("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "php-apache-binary",
			FileGlob: "**/libphp*.so",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`),
			Package: "libphp",
			PURL:    mustPURL("pkg:generic/php@version"),
			CPEs:    singleCPE("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "php-composer-binary",
			FileGlob: "**/composer*",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)'pretty_version'\s*=>\s*'(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)'`),
			Package: "composer",
			PURL:    mustPURL("pkg:generic/composer@version"),
			CPEs:    singleCPE("cpe:2.3:a:getcomposer:composer:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "httpd-binary",
			FileGlob: "**/httpd",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)Apache\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "httpd",
			PURL:    mustPURL("pkg:generic/httpd@version"),
			CPEs:    singleCPE("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "memcached-binary",
			FileGlob: "**/memcached",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)memcached\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "memcached",
			PURL:    mustPURL("pkg:generic/memcached@version"),
			CPEs:    singleCPE("cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "traefik-binary",
			FileGlob: "**/traefik",
			EvidenceMatcher: FileContentsVersionMatcher(
				// [NUL]v1.7.34[NUL]
				// [NUL]2.9.6[NUL]
				// 3.0.4[NUL]
				`(?m)(\x00|\x{FFFD})?v?(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00`),
			Package: "traefik",
			PURL:    mustPURL("pkg:generic/traefik@version"),
			CPEs:    singleCPE("cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "arangodb-binary",
			FileGlob: "**/arangosh",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)\x00*(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+)?)\s\[linux\]`),
			Package: "arangodb",
			PURL:    mustPURL("pkg:generic/arangodb@version"),
			CPEs:    singleCPE("cpe:2.3:a:arangodb:arangodb:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
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
			CPEs:    singleCPE("cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "mysql-binary",
			FileGlob: "**/mysql",
			EvidenceMatcher: evidenceMatchers(
				// shutdown[NUL]8.0.37[NUL][NUL][NUL][NUL][NUL]mysql_real_esc
				FileContentsVersionMatcher(`\x00(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)\x00+mysql`),
				// /export/home/pb2/build/sb_0-26781090-1516292385.58/release/mysql-8.0.4-rc/mysys_ssl/my_default.cc
				FileContentsVersionMatcher(`(?m).*/mysql-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
			),
			Package: "mysql",
			PURL:    mustPURL("pkg:generic/mysql@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "mysql-binary",
			FileGlob: "**/mysql",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m).*/percona-server-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
			Package: "percona-server",
			PURL:    mustPURL("pkg:generic/percona-server@version"),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				cpe.Must("cpe:2.3:a:percona:percona_server:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
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
				cpe.Must("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				cpe.Must("cpe:2.3:a:percona:percona_server:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				cpe.Must("cpe:2.3:a:percona:xtradb_cluster:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
			},
		},
		{
			Class:    "xtrabackup-binary",
			FileGlob: "**/xtrabackup",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m).*/percona-xtrabackup-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
			Package: "percona-xtrabackup",
			PURL:    mustPURL("pkg:generic/percona-xtrabackup@version"),
			CPEs:    singleCPE("cpe:2.3:a:percona:xtrabackup:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "mariadb-binary",
			FileGlob: "**/{mariadb,mysql}",
			EvidenceMatcher: FileContentsVersionMatcher(
				// 10.6.15-MariaDB
				`(?m)(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)-MariaDB`),
			Package: "mariadb",
			PURL:    mustPURL("pkg:generic/mariadb@version"),
			CPEs:    singleCPE("cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "rust-standard-library-linux",
			FileGlob: "**/libstd-????????????????.so",
			EvidenceMatcher: FileContentsVersionMatcher(
				// clang LLVM (rustc version 1.48.0 (7eac88abb 2020-11-16))
				`(?m)(\x00)clang LLVM \(rustc version (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)) \(\w+ \d{4}\-\d{2}\-\d{2}\)`),
			Package: "rust",
			PURL:    mustPURL("pkg:generic/rust@version"),
			CPEs:    singleCPE("cpe:2.3:a:rust-lang:rust:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "rust-standard-library-macos",
			FileGlob: "**/libstd-????????????????.dylib",
			EvidenceMatcher: FileContentsVersionMatcher(
				// c 1.48.0 (7eac88abb 2020-11-16)
				`(?m)c (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)) \(\w+ \d{4}\-\d{2}\-\d{2}\)`),
			Package: "rust",
			PURL:    mustPURL("pkg:generic/rust@version"),
			CPEs:    singleCPE("cpe:2.3:a:rust-lang:rust:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
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
			CPEs:    singleCPE("cpe:2.3:a:ruby-lang:ruby:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
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
			CPEs:    singleCPE("cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "erlang-alpine-binary",
			FileGlob: "**/beam.smp",
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
			CPEs:    singleCPE("cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
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
			CPEs:    singleCPE("cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "swipl-binary",
			FileGlob: "**/swipl",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)swipl-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\/`,
			),
			Package: "swipl",
			PURL:    mustPURL("pkg:generic/swipl@version"),
			CPEs:    singleCPE("cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "dart-binary",
			FileGlob: "**/dart",
			EvidenceMatcher: FileContentsVersionMatcher(
				// MathAtan[NUL]2.12.4 (stable)
				// "%s"[NUL]3.0.0 (stable)
				// Dart,GC"[NUL]3.5.2 (stable)
				// Dart,GC"[NUL]3.6.0-216.1.beta (beta)
				`(?m)\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+(\.[0-9]+)?\.beta)?) `,
			),
			Package: "dart",
			PURL:    mustPURL("pkg:generic/dart@version"),
			CPEs:    singleCPE("cpe:2.3:a:dart:dart_software_development_kit:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "haskell-ghc-binary",
			FileGlob: "**/ghc*",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)\x00GHC (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`,
			),
			Package: "haskell/ghc",
			PURL:    mustPURL("pkg:generic/haskell/ghc@version"),
			CPEs:    singleCPE("cpe:2.3:a:haskell:ghc:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "haskell-cabal-binary",
			FileGlob: "**/cabal",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)\x00Cabal-(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)-`,
			),
			Package: "haskell/cabal",
			PURL:    mustPURL("pkg:generic/haskell/cabal@version"),
			CPEs:    singleCPE("cpe:2.3:a:haskell:cabal:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "haskell-stack-binary",
			FileGlob: "**/stack",
			EvidenceMatcher: FileContentsVersionMatcher(
				`(?m)Version\s*(?P<version>[0-9]+\.[0-9]+\.[0-9]+),\s*Git`,
			),
			Package: "haskell/stack",
			PURL:    mustPURL("pkg:generic/haskell/stack@version"),
			CPEs:    singleCPE("cpe:2.3:a:haskell:stack:*:*:*:*:*:*:*:*"),
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
			CPEs:    singleCPE("cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
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
				cpe.Must("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				cpe.Must("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
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
			CPEs:    singleCPE("cpe:2.3:a:gnu:bash:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
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
			CPEs:    singleCPE("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
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
			CPEs:    singleCPE("cpe:2.3:a:gnu:gcc:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
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
			CPEs:    singleCPE("cpe:2.3:a:treasuredata:fluent_bit:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
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
			CPEs:    singleCPE("cpe:2.3:a:wp-cli:wp-cli:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "curl-binary",
			FileGlob: "**/curl",
			EvidenceMatcher: FileContentsVersionMatcher(
				`curl/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`,
			),
			Package: "curl",
			PURL:    mustPURL("pkg:generic/curl@version"),
			CPEs:    singleCPE("cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "lighttpd-binary",
			FileGlob: "**/lighttpd",
			EvidenceMatcher: FileContentsVersionMatcher(
				`\x00lighttpd/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`,
			),
			Package: "lighttpd",
			PURL:    mustPURL("pkg:generic/lighttpd@version"),
			CPEs:    singleCPE("cpe:2.3:a:lighttpd:lighttpd:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "proftpd-binary",
			FileGlob: "**/proftpd",
			EvidenceMatcher: FileContentsVersionMatcher(
				`\x00ProFTPD Version (?P<version>[0-9]+\.[0-9]+\.[0-9]+[a-z]?)\x00`,
			),
			Package: "proftpd",
			PURL:    mustPURL("pkg:generic/proftpd@version"),
			CPEs:    singleCPE("cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "zstd-binary",
			FileGlob: "**/zstd",
			EvidenceMatcher: FileContentsVersionMatcher(
				`\x00v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`,
			),
			Package: "zstd",
			PURL:    mustPURL("pkg:generic/zstd@version"),
			CPEs:    singleCPE("cpe:2.3:a:facebook:zstandard:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "xz-binary",
			FileGlob: "**/xz",
			EvidenceMatcher: FileContentsVersionMatcher(
				`\x00xz \(XZ Utils\) (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`,
			),
			Package: "xz",
			PURL:    mustPURL("pkg:generic/xz@version"),
			CPEs:    singleCPE("cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "gzip-binary",
			FileGlob: "**/gzip",
			EvidenceMatcher: FileContentsVersionMatcher(
				`\x00(?P<version>[0-9]+\.[0-9]+)\x00`,
			),
			Package: "gzip",
			PURL:    mustPURL("pkg:generic/gzip@version"),
			CPEs:    singleCPE("cpe:2.3:a:gnu:gzip:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "sqlcipher-binary",
			FileGlob: "**/sqlcipher",
			EvidenceMatcher: FileContentsVersionMatcher(
				`[^0-9]\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`,
			),
			Package: "sqlcipher",
			PURL:    mustPURL("pkg:generic/sqlcipher@version"),
			CPEs:    singleCPE("cpe:2.3:a:zetetic:sqlcipher:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "jq-binary",
			FileGlob: "**/jq",
			EvidenceMatcher: FileContentsVersionMatcher(
				`\x00(?P<version>[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]+)?)\x00`,
			),
			Package: "jq",
			PURL:    mustPURL("pkg:generic/jq@version"),
			CPEs:    singleCPE("cpe:2.3:a:jqlang:jq:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
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
	// ruby 3.4.0dev (2024-09-15T01:06:11Z master 532af89e3b) [x86_64-linux]
	// ruby 3.4.0preview1 (2024-05-16 master 9d69619623) [x86_64-linux]
	// ruby 3.3.0rc1 (2023-12-11 master a49643340e) [x86_64-linux]
	// ruby 3.2.1 (2023-02-08 revision 31819e82c8) [x86_64-linux]
	// ruby 2.7.7p221 (2022-11-24 revision 168ec2b1e5) [x86_64-linux]
	`(?m)ruby (?P<version>[0-9]+\.[0-9]+\.[0-9]+((p|preview|rc|dev)[0-9]*)?) `)
