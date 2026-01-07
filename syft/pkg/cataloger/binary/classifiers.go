package binary

import (
	"fmt"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/binutils"
)

// in both binaries and shared libraries, the version pattern is [NUL]3.11.2[NUL]
var pythonVersionTemplate = `(?m)\x00(?P<version>{{ .version }}[-._a-zA-Z0-9]*)\x00`

//nolint:funlen
func DefaultClassifiers() []binutils.Classifier {
	m := binutils.ContextualEvidenceMatchers{CatalogerName: catalogerName}

	var libpythonMatcher = m.FileNameTemplateVersionMatcher(
		`(?:.*/|^)libpython(?P<version>[0-9]+(?:\.[0-9]+)+)[a-z]?\.so.*$`,
		pythonVersionTemplate,
	)

	var rubyMatcher = m.FileContentsVersionMatcher(
		// ruby 3.4.0dev (2024-09-15T01:06:11Z master 532af89e3b) [x86_64-linux]
		// ruby 3.4.0preview1 (2024-05-16 master 9d69619623) [x86_64-linux]
		// ruby 3.3.0rc1 (2023-12-11 master a49643340e) [x86_64-linux]
		// ruby 3.2.1 (2023-02-08 revision 31819e82c8) [x86_64-linux]
		// ruby 2.7.7p221 (2022-11-24 revision 168ec2b1e5) [x86_64-linux]
		`(?m)ruby (?P<version>[0-9]+\.[0-9]+\.[0-9]+((p|preview|rc|dev)[0-9]*)?) `)

	classifiers := []binutils.Classifier{
		{
			Class:    "python-binary",
			FileGlob: "**/python*",
			EvidenceMatcher: binutils.MatchAny(
				// try to find version information from libpython shared libraries
				binutils.SharedLibraryLookup(
					`^libpython[0-9]+(?:\.[0-9]+)+[a-z]?\.so.*$`,
					libpythonMatcher),
				// check for version information in the binary
				m.FileNameTemplateVersionMatcher(
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
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)\[PyPy (?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "pypy",
			PURL:    mustPURL("pkg:generic/pypy@version"),
		},
		{
			Class:    "go-binary",
			FileGlob: "**/go",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)?)\x00`),
			Package: "go",
			PURL:    mustPURL("pkg:generic/go@version"),
			CPEs:    singleCPE("cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "julia-binary",
			FileGlob: "**/libjulia-internal.so",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)__init__\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00verify`),
			Package: "julia",
			PURL:    mustPURL("pkg:generic/julia@version"),
			CPEs:    singleCPE("cpe:2.3:a:julialang:julia:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "helm",
			FileGlob: "**/helm",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)\x00v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`),
			Package: "helm",
			PURL:    mustPURL("pkg:golang/helm.sh/helm@version"),
			CPEs:    singleCPE("cpe:2.3:a:helm:helm:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "redis-binary",
			FileGlob: "**/redis-server",
			EvidenceMatcher: binutils.MatchAny(
				// matches most recent versions of redis (~v7), e.g. "7.0.14buildkitsandbox-1702957741000000000"
				m.FileContentsVersionMatcher(`[^\d](?P<version>\d+.\d+\.\d+)buildkitsandbox-\d+`),
				// matches against older versions of redis (~v3 - v6), e.g. "4.0.11841ce7054bd9-1542359302000000000"
				m.FileContentsVersionMatcher(`[^\d](?P<version>[0-9]+\.[0-9]+\.[0-9]+)\w{12}-\d+`),
				// matches against older versions of redis (~v2), e.g. "Server started, Redis version 2.8.23"
				m.FileContentsVersionMatcher(`Redis version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			),
			Package: "redis",
			PURL:    mustPURL("pkg:generic/redis@version"),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:redislabs:redis:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				cpe.Must("cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
			},
		},
		{
			Class:    "valkey-binary",
			FileGlob: "**/valkey-server",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				// valkey9.0.0buildkitsandbox-1764887574000000000
				`[^\d](?P<version>\d+.\d+\.\d+)buildkitsandbox-\d+`),
			Package: "valkey",
			PURL:    mustPURL("pkg:generic/valkey@version"),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:lfprojects:valkey:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				cpe.Must("cpe:2.3:a:linuxfoundation:valkey:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
				cpe.Must("cpe:2.3:a:valkey-io:valkey:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
			},
		},
		{
			Class:    "nodejs-binary",
			FileGlob: "**/node",
			EvidenceMatcher: binutils.MatchAny(
				// [NUL]node v0.10.48[NUL]
				// [NUL]v0.12.18[NUL]
				// [NUL]v4.9.1[NUL]
				// node.js/v22.9.0
				m.FileContentsVersionMatcher(`(?m)\x00(node )?v(?P<version>(0|4|5|6)\.[0-9]+\.[0-9]+)\x00`),
				m.FileContentsVersionMatcher(`(?m)node\.js\/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			),
			Package: "node",
			PURL:    mustPURL("pkg:generic/node@version"),
			CPEs:    singleCPE("cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "go-binary-hint",
			FileGlob: "**/VERSION*",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)?(-[0-9a-f]{7})?)`),
			Package: "go",
			PURL:    mustPURL("pkg:generic/go@version"),
			CPEs:    singleCPE("cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "busybox-binary",
			FileGlob: "**/busybox",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)BusyBox\s+v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "busybox",
			PURL:    mustPURL("pkg:generic/busybox@version"),
			CPEs:    singleCPE("cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "util-linux-binary",
			FileGlob: "**/getopt",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`\x00util-linux\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`),
			Package: "util-linux",
			PURL:    mustPURL("pkg:generic/util-linux@version"),
			CPEs:    singleCPE("cpe:2.3:a:kernel:util-linux:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "haproxy-binary",
			FileGlob: "**/haproxy",
			EvidenceMatcher: binutils.MatchAny(
				m.FileContentsVersionMatcher(`(?m)version (?P<version>[0-9]+\.[0-9]+(\.|-dev|-rc)[0-9]+)(-[a-z0-9]{7})?, released 20`),
				m.FileContentsVersionMatcher(`(?m)HA-Proxy version (?P<version>[0-9]+\.[0-9]+(\.|-dev)[0-9]+)`),
				m.FileContentsVersionMatcher(`(?m)(?P<version>[0-9]+\.[0-9]+(\.|-dev)[0-9]+)-[0-9a-zA-Z]{7}.+HAProxy version`),
			),
			Package: "haproxy",
			PURL:    mustPURL("pkg:generic/haproxy@version"),
			CPEs:    singleCPE("cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "perl-binary",
			FileGlob: "**/perl",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)\/usr\/local\/lib\/perl\d\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "perl",
			PURL:    mustPURL("pkg:generic/perl@version"),
			CPEs:    singleCPE("cpe:2.3:a:perl:perl:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "php-composer-binary",
			FileGlob: "**/composer*",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)'pretty_version'\s*=>\s*'(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)'`),
			Package: "composer",
			PURL:    mustPURL("pkg:generic/composer@version"),
			CPEs:    singleCPE("cpe:2.3:a:getcomposer:composer:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "httpd-binary",
			FileGlob: "**/httpd",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)Apache\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "httpd",
			PURL:    mustPURL("pkg:generic/httpd@version"),
			CPEs:    singleCPE("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "memcached-binary",
			FileGlob: "**/memcached",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)memcached\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "memcached",
			PURL:    mustPURL("pkg:generic/memcached@version"),
			CPEs:    singleCPE("cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "traefik-binary",
			FileGlob: "**/traefik",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				// [NUL]v1.7.34[NUL]
				// [NUL]2.9.6[NUL]
				// 3.0.4[NUL]
				`(?m)(\x00v?|\x{FFFD}.?)(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00`),
			Package: "traefik",
			PURL:    mustPURL("pkg:generic/traefik@version"),
			CPEs:    singleCPE("cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "arangodb-binary",
			FileGlob: "**/arangosh",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)\x00*(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-[0-9]+)?)\s\[linux\]`),
			Package: "arangodb",
			PURL:    mustPURL("pkg:generic/arangodb@version"),
			CPEs:    singleCPE("cpe:2.3:a:arangodb:arangodb:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "postgresql-binary",
			FileGlob: "**/postgres",
			EvidenceMatcher: m.FileContentsVersionMatcher(
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
			EvidenceMatcher: binutils.MatchAny(
				// shutdown[NUL]8.0.37[NUL][NUL][NUL][NUL][NUL]mysql_real_esc
				m.FileContentsVersionMatcher(`\x00(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)\x00+mysql`),
				// /export/home/pb2/build/sb_0-26781090-1516292385.58/release/mysql-8.0.4-rc/mysys_ssl/my_default.cc
				m.FileContentsVersionMatcher(`(?m).*/mysql-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
			),
			Package: "mysql",
			PURL:    mustPURL("pkg:generic/mysql@version"),
			CPEs:    singleCPE("cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "mysql-binary",
			FileGlob: "**/mysql",
			EvidenceMatcher: m.FileContentsVersionMatcher(
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
			EvidenceMatcher: m.FileContentsVersionMatcher(
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
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m).*/percona-xtrabackup-(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
			Package: "percona-xtrabackup",
			PURL:    mustPURL("pkg:generic/percona-xtrabackup@version"),
			CPEs:    singleCPE("cpe:2.3:a:percona:xtrabackup:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "mariadb-binary",
			FileGlob: "**/{mariadb,mysql}",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				// 10.6.15-MariaDB
				`(?m)(?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)-MariaDB`),
			Package: "mariadb",
			PURL:    mustPURL("pkg:generic/mariadb@version"),
			CPEs:    singleCPE("cpe:2.3:a:mariadb:mariadb:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "rust-standard-library-linux",
			FileGlob: "**/libstd-????????????????.so",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				// clang LLVM (rustc version 1.48.0 (7eac88abb 2020-11-16))
				`(?m)(\x00)clang LLVM \(rustc version (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)) \(\w+ \d{4}\-\d{2}\-\d{2}\)`),
			Package: "rust",
			PURL:    mustPURL("pkg:generic/rust@version"),
			CPEs:    singleCPE("cpe:2.3:a:rust-lang:rust:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "rust-standard-library-macos",
			FileGlob: "**/libstd-????????????????.dylib",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				// c 1.48.0 (7eac88abb 2020-11-16)
				`(?m)c (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)) \(\w+ \d{4}\-\d{2}\-\d{2}\)`),
			Package: "rust",
			PURL:    mustPURL("pkg:generic/rust@version"),
			CPEs:    singleCPE("cpe:2.3:a:rust-lang:rust:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "ruby-binary",
			FileGlob: "**/ruby",
			EvidenceMatcher: binutils.MatchAny(
				rubyMatcher,
				binutils.SharedLibraryLookup(
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
			EvidenceMatcher: binutils.MatchAny(
				m.FileContentsVersionMatcher(
					// <artificial>[NUL]/usr/src/otp_src_25.3.2.6/erts/
					`(?m)/src/otp_src_(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/`,
				),
				m.FileContentsVersionMatcher(
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
			EvidenceMatcher: binutils.MatchAny(
				m.FileContentsVersionMatcher(
					// <artificial>[NUL]/usr/src/otp_src_25.3.2.6/erts/
					`(?m)/src/otp_src_(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/`,
				),
				m.FileContentsVersionMatcher(
					// <artificial>[NUL]/usr/local/src/otp-25.3.2.7/erts/
					`(?m)/usr/local/src/otp-(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/`,
				),
				m.FileContentsVersionMatcher(
					// [NUL][NUL]26.1.2[NUL][NUL][NUL][NUL][NUL][NUL][NUL]NUL[NUL][NUL]Erlang/OTP
					`\x00+(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)\x00+Erlang/OTP`,
				),
			),
			Package: "erlang",
			PURL:    mustPURL("pkg:generic/erlang@version"),
			CPEs:    singleCPE("cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "erlang-library",
			FileGlob: "**/liberts_internal.a",
			EvidenceMatcher: binutils.MatchAny(
				m.FileContentsVersionMatcher(
					// <artificial>[NUL]/usr/src/otp_src_25.3.2.6/erts/
					`(?m)/src/otp_src_(?P<version>[0-9]+\.[0-9]+(\.[0-9]+){0,2}(-rc[0-9])?)/erts/`,
				),
				m.FileContentsVersionMatcher(
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
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)swipl-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\/`,
			),
			Package: "swipl",
			PURL:    mustPURL("pkg:generic/swipl@version"),
			CPEs:    singleCPE("cpe:2.3:a:erlang:erlang\\/otp:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "dart-binary",
			FileGlob: "**/dart",
			EvidenceMatcher: m.FileContentsVersionMatcher(
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
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)\x00GHC (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`,
			),
			Package: "haskell/ghc",
			PURL:    mustPURL("pkg:generic/haskell/ghc@version"),
			CPEs:    singleCPE("cpe:2.3:a:haskell:ghc:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "haskell-cabal-binary",
			FileGlob: "**/cabal",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)\x00Cabal-(?P<version>[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?)-`,
			),
			Package: "haskell/cabal",
			PURL:    mustPURL("pkg:generic/haskell/cabal@version"),
			CPEs:    singleCPE("cpe:2.3:a:haskell:cabal:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "haskell-stack-binary",
			FileGlob: "**/stack",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)Version\s*(?P<version>[0-9]+\.[0-9]+\.[0-9]+),\s*Git`,
			),
			Package: "haskell/stack",
			PURL:    mustPURL("pkg:generic/haskell/stack@version"),
			CPEs:    singleCPE("cpe:2.3:a:haskell:stack:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "consul-binary",
			FileGlob: "**/consul",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				// NOTE: This is brittle and may not work for past or future versions
				`CONSUL_VERSION: (?P<version>\d+\.\d+\.\d+)`,
			),
			Package: "consul",
			PURL:    mustPURL("pkg:golang/github.com/hashicorp/consul@version"),
			CPEs:    singleCPE("cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "hashicorp-vault-binary",
			FileGlob: "**/vault",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				// revoke1.18.0
				`(?m)revoke(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "github.com/hashicorp/vault",
			PURL:    mustPURL("pkg:golang/github.com/hashicorp/vault@version"),
			CPEs:    singleCPE("cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "nginx-binary",
			FileGlob: "**/nginx",
			EvidenceMatcher: m.FileContentsVersionMatcher(
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
			EvidenceMatcher: m.FileContentsVersionMatcher(
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
			EvidenceMatcher: m.FileContentsVersionMatcher(
				// [NUL]OpenSSL 3.1.4'
				// [NUL]OpenSSL 1.1.1w'
				`\x00OpenSSL (?P<version>[0-9]+\.[0-9]+\.[0-9]+([a-z]+|-alpha[0-9]|-beta[0-9]|-rc[0-9])?)`,
			),
			Package: "openssl",
			PURL:    mustPURL("pkg:generic/openssl@version"),
			CPEs:    singleCPE("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "gcc-binary",
			FileGlob: "**/gcc",
			EvidenceMatcher: m.FileContentsVersionMatcher(
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
			EvidenceMatcher: m.FileContentsVersionMatcher(
				// [NUL]3.0.2[NUL]%sFluent Bit
				// [NUL]2.2.3[NUL]Fluent Bit
				// [NUL]2.2.1[NUL][NUL][NUL]Fluent Bit
				// [NUL]1.7.0[NUL]\x1b[1m[NUL]%sFluent Bit (versions 1.7.0-dev-3 through 1.7.0-dev-9 and 1.7.0-rc4 through 1.7.0-rc8)
				// [NUL][NUL]1.3.10[NUL][NUL]Fluent Bit v%s
				`\x00(\x00)?(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00(\x1b\[1m\x00|\x00|\x00\x00)?(%s)?Fluent`,
			),
			Package: "fluent-bit",
			PURL:    mustPURL("pkg:github/fluent/fluent-bit@version"),
			CPEs:    singleCPE("cpe:2.3:a:treasuredata:fluent_bit:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "wordpress-cli-binary",
			FileGlob: "**/wp",
			EvidenceMatcher: m.FileContentsVersionMatcher(
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
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`curl/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`,
			),
			Package: "curl",
			PURL:    mustPURL("pkg:generic/curl@version"),
			CPEs:    singleCPE("cpe:2.3:a:haxx:curl:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "lighttpd-binary",
			FileGlob: "**/lighttpd",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`\x00lighttpd/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`,
			),
			Package: "lighttpd",
			PURL:    mustPURL("pkg:generic/lighttpd@version"),
			CPEs:    singleCPE("cpe:2.3:a:lighttpd:lighttpd:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "proftpd-binary",
			FileGlob: "**/proftpd",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`\x00ProFTPD Version (?P<version>[0-9]+\.[0-9]+\.[0-9]+[a-z]?)\x00`,
			),
			Package: "proftpd",
			PURL:    mustPURL("pkg:generic/proftpd@version"),
			CPEs:    singleCPE("cpe:2.3:a:proftpd:proftpd:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "zstd-binary",
			FileGlob: "**/zstd",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`\x00v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`,
			),
			Package: "zstd",
			PURL:    mustPURL("pkg:generic/zstd@version"),
			CPEs:    singleCPE("cpe:2.3:a:facebook:zstandard:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "xz-binary",
			FileGlob: "**/xz",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`\x00xz \(XZ Utils\) (?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`,
			),
			Package: "xz",
			PURL:    mustPURL("pkg:generic/xz@version"),
			CPEs:    singleCPE("cpe:2.3:a:tukaani:xz:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "gzip-binary",
			FileGlob: "**/gzip",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`\x00(?P<version>[0-9]+\.[0-9]+)\x00`,
			),
			Package: "gzip",
			PURL:    mustPURL("pkg:generic/gzip@version"),
			CPEs:    singleCPE("cpe:2.3:a:gnu:gzip:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "sqlcipher-binary",
			FileGlob: "**/sqlcipher",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`[^0-9]\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`,
			),
			Package: "sqlcipher",
			PURL:    mustPURL("pkg:generic/sqlcipher@version"),
			CPEs:    singleCPE("cpe:2.3:a:zetetic:sqlcipher:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "jq-binary",
			FileGlob: "**/jq",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`\x00(?P<version>[0-9]{1,3}\.[0-9]{1,3}(\.[0-9]+)?)\x00`,
			),
			Package: "jq",
			PURL:    mustPURL("pkg:generic/jq@version"),
			CPEs:    singleCPE("cpe:2.3:a:jqlang:jq:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "chrome-binary",
			FileGlob: "**/chrome",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				// [NUL]127.0.6533.119[NUL]Default
				`\x00(?P<version>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\x00Default`,
			),
			Package: "chrome",
			PURL:    mustPURL("pkg:generic/chrome@version"),
			CPEs:    singleCPE("cpe:2.3:a:google:chrome:*:*:*:*:*:*:*:*"),
		},
		{
			Class:    "ffmpeg-binary",
			FileGlob: "**/ffmpeg",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				// Pattern found in the binary: "%s version 7.1.1" or "%s version 6.0"
				// When executed outputs: "ffmpeg version 7.1.1" or "ffmpeg version 6.0"
				`(?m)%s version (?P<version>[0-9]+\.[0-9]+(\.[0-9]+)?)`,
			),
			Package: "ffmpeg",
			PURL:    mustPURL("pkg:generic/ffmpeg@version"),
			CPEs:    singleCPE("cpe:2.3:a:ffmpeg:ffmpeg:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "ffmpeg-library",
			FileGlob: "**/libav*",
			EvidenceMatcher: binutils.MatchAny(
				// Primary pattern: FFmpeg version found in most libraries
				m.FileContentsVersionMatcher(`(?m)FFmpeg version (?P<version>[0-9]+\.[0-9]+(\.[0-9]+)?)`),
				// Fallback: library-specific version patterns for libavcodec and libavformat
				m.FileContentsVersionMatcher(`(?m)Lavc(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
				m.FileContentsVersionMatcher(`(?m)Lavf(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			),
			Package: "ffmpeg",
			PURL:    mustPURL("pkg:generic/ffmpeg@version"),
			CPEs:    singleCPE("cpe:2.3:a:ffmpeg:ffmpeg:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "ffmpeg-library",
			FileGlob: "**/libswresample*",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				// FFmpeg version pattern for libswresample
				`(?m)FFmpeg version (?P<version>[0-9]+\.[0-9]+(\.[0-9]+)?)`),
			Package: "ffmpeg",
			PURL:    mustPURL("pkg:generic/ffmpeg@version"),
			CPEs:    singleCPE("cpe:2.3:a:ffmpeg:ffmpeg:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "elixir-binary",
			FileGlob: "**/elixir",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)ELIXIR_VERSION=(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			Package: "elixir",
			PURL:    mustPURL("pkg:generic/elixir@version"),
			CPEs: []cpe.CPE{
				cpe.Must("cpe:2.3:a:elixir-lang:elixir:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
			},
		},
		{
			Class:    "elixir-library",
			FileGlob: "**/elixir/ebin/elixir.app",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				`(?m)\{vsn,"(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-[a-z0-9]+)?)"\}`),
			Package: "elixir",
			PURL:    mustPURL("pkg:generic/elixir@version"),
			CPEs:    singleCPE("cpe:2.3:a:elixir-lang:elixir:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "istio-binary",
			FileGlob: "**/pilot-discovery",
			EvidenceMatcher: binutils.MatchAny(
				// [NUL]1.26.8[NUL][NUL]1.26.8[NUL]
				// [NUL]1.3.7[NUL][NUL][NUL]1.3.8[NUL]
				m.FileContentsVersionMatcher(`[0-9]+\.[0-9]+\.[0-9]+\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+`),
				// Clean[NUL][NUL][NUL]1.8.0[NUL]
				m.FileContentsVersionMatcher(`Clean\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+`),
				// 1.1.17[NUL]...S=v<y5
				m.FileContentsVersionMatcher(`(?s)(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+.{1,100}S?=v<y5`),
			),
			Package: "pilot-discovery",
			PURL:    mustPURL("pkg:generic/istio@version"),
			CPEs:    singleCPE("cpe:2.3:a:istio:istio:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "istio-binary",
			FileGlob: "**/pilot-agent",
			EvidenceMatcher: binutils.MatchAny(
				// [NUL]1.26.8[NUL][NUL]1.26.8[NUL]
				m.FileContentsVersionMatcher(`[0-9]+\.[0-9]+\.[0-9]+\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+`),
				// Clean[NUL][NUL][NUL]1.8.0[NUL]
				m.FileContentsVersionMatcher(`Clean\x00+(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+`),
				// 1.1.17[NUL]...S=v<y5
				m.FileContentsVersionMatcher(`(?s)(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00+.{1,100}S?=v<y5`),
			),
			Package: "pilot-agent",
			PURL:    mustPURL("pkg:generic/istio@version"),
			CPEs:    singleCPE("cpe:2.3:a:istio:istio:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "grafana-binary",
			FileGlob: "**/grafana",
			EvidenceMatcher: binutils.MatchAny(
				// [NUL][NUL][NUL][NUL]release-12.3.1[NUL][NUL][NUL][NUL]
				m.FileContentsVersionMatcher(`\x00+release-(?P<version>[0-9]{2}\.[0-9]+\.[0-9]+)\x00+`),
				// HEAD[NUL][NUL][NUL][NUL]12.0.0[NUL][NUL]$a
				// 11.0.0[NUL][NUL]$a
				m.FileContentsVersionMatcher(`(?P<version>[0-9]{2}\.[0-9]+\.[0-9]+)\x00+\$a`),
				// [NUL]0xDC0xBF10.4.19[NUL]
				m.FileContentsVersionMatcher(`\x00.(?P<version>10\.[0-9]+\.[0-9]+)\x00`),
				// 9.5.21[NUL][NUL]v9.5.x[NUL][NUL][NUL][NUL][NUL][NUL]$a
				m.FileContentsVersionMatcher(`(?P<version>9\.[0-9]+\.[0-9]+)\x00\x00v`),
			),
			Package: "grafana",
			PURL:    mustPURL("pkg:generic/grafana@version"),
			CPEs:    singleCPE("cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "grafana-binary",
			FileGlob: "**/grafana-server",
			EvidenceMatcher: m.FileContentsVersionMatcher(
				// HEAD[NUL][NUL][NUL][NUL]9.0.0[NUL]:[NUL]
				// HEAD[NUL][NUL][NUL][NUL]:[NUL][NUL][NUL][NUL][NUL][NUL][NUL]7.5.17[NUL][NUL][NUL][NUL]
				// HEAD[NUL][NUL][NUL][NUL]m[NUL]...[NUL][NUL]6.7.6[NUL][NUL][NUL].[NUL][NUL][NUL][NUL][NUL][NUL][NUL]:
				`HEAD\x00+.*\x00+(?P<version>[0-9]\.[0-9]+\.[0-9]+)\x00+`),
			Package: "grafana",
			PURL:    mustPURL("pkg:generic/grafana@version"),
			CPEs:    singleCPE("cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
		{
			Class:    "envoy-binary",
			FileGlob: "**/envoy",
			EvidenceMatcher: binutils.MatchAny(
				// 1.3x [NUL]1.36.4[NUL]...envoy_reloadable_features
				// 1.34.5 [NUL]1.34.5[NUL]...envoy.reloadable_features
				m.FileContentsVersionMatcher(`(?s)\x00(?P<version>1\.3[0-9]\.[0-9]+(-dev)?)\x00.{0,1000}envoy_reloadable_features`),
				m.FileContentsVersionMatcher(`(?s)\x00(?P<version>1\.34\.5)\x00.{0,200}envoy\.reloadable_features`),
				// 1.2x envoy_quic_...[NUL]1.28.7[NUL]
				m.FileContentsVersionMatcher(`(?s)envoy_quic_.{0,1000}\x00(?P<version>1\.2[0-9]\.[0-9]+(-dev)?)\x00`),
				// 1.2x [NUL]1.20.7[NUL]Unable to
				// 1.1x [NUL]1.18.6-dev[NUL]Unable to
				m.FileContentsVersionMatcher(`(?s)\x00(?P<version>1\.[12][0-9]\.[0-9]+(-dev)?)\x00.{0,1000}Unable to`),
				// 1.2x [NUL]1.22.11[NUL]...ValidationError
				// 1.1x [NUL]1.14.3[NUL]...ValidationError
				m.FileContentsVersionMatcher(`(?s)\x00(?P<version>1\.2[0-9]\.[0-9]+(-dev)?)\x00.{0,580}ValidationError`),
				m.FileContentsVersionMatcher(`(?s)\x00(?P<version>1\.1[0-9]\.[0-9]+(-dev)?)\x00.{0,1000}ValidationError`),
				// 1.1x [source...[NUL]1.11.0[NUL]/
				m.FileContentsVersionMatcher(`(?s)\[source/.{0,200}\x00(?P<version>1\.1[0-9]\.[0-9]+(-dev)?)\x00`),
				// 1.x [NUL]1.6.0[NUL]RELEASE
				m.FileContentsVersionMatcher(`(?s)\x00(?P<version>1\.[0-9]\.[0-9]+(-dev)?)\x00.{0,20}RELEASE`),
			),
			Package: "envoy",
			PURL:    mustPURL("pkg:generic/envoy@version"),
			CPEs:    singleCPE("cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*", cpe.NVDDictionaryLookupSource),
		},
	}

	return append(classifiers, defaultJavaClassifiers()...)
}

// singleCPE returns a []cpe.CPE with Source: Generated based on the cpe string or panics if the
// cpe string cannot be parsed into valid CPE Attributes
func singleCPE(cpeString string, source ...cpe.Source) []cpe.CPE {
	src := cpe.GeneratedSource
	if len(source) > 0 {
		src = source[0]
	}
	return []cpe.CPE{
		cpe.Must(cpeString, src),
	}
}

func mustPURL(purl string) packageurl.PackageURL {
	p, err := packageurl.FromString(purl)
	if err != nil {
		panic(fmt.Sprintf("invalid PURL: %s", p))
	}
	return p
}
