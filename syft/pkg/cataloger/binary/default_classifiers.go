package binary

import (
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
)

var defaultClassifiers = []classifier{
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
			cpe.Must("cpe:2.3:a:python_software_foundation:python:*:*:*:*:*:*:*:*"),
			cpe.Must("cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"),
		},
	},
	{
		Class:           "python-binary-lib",
		FileGlob:        "**/libpython*.so*",
		EvidenceMatcher: libpythonMatcher,
		Package:         "python",
		PURL:            mustPURL("pkg:generic/python@version"),
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:python_software_foundation:python:*:*:*:*:*:*:*:*"),
			cpe.Must("cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"),
		},
	},
	{
		Class:    "go-binary",
		FileGlob: "**/go",
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)?)\x00`),
		Package: "go",
		PURL:    mustPURL("pkg:generic/go@version"),
		CPEs:    singleCPE("cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*"),
	},
	{
		Class:    "helm",
		FileGlob: "**/helm",
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)\x00v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\x00`),
		Package: "helm",
		PURL:    mustPURL("pkg:golang/helm.sh/helm@version"),
		CPEs:    singleCPE("cpe:2.3:a:helm:helm:*:*:*:*:*:*:*"),
	},
	{
		Class:    "redis-binary",
		FileGlob: "**/redis-server",
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?s)payload %5.*(?P<version>\d.\d\.\d\d*?)[a-z0-9]{12}-[0-9]{19}`),
		Package: "redis",
		PURL:    mustPURL("pkg:generic/redis@version"),
		CPEs:    singleCPE("cpe:2.3:a:redislabs:redis:*:*:*:*:*:*:*:*"),
	},
	{
		Class:    "java-binary-openjdk",
		FileGlob: "**/java",
		EvidenceMatcher: fileContentsVersionMatcher(
			// [NUL]openjdk[NUL]java[NUL]0.0[NUL]11.0.17+8-LTS[NUL]
			// [NUL]openjdk[NUL]java[NUL]1.8[NUL]1.8.0_352-b08[NUL]
			`(?m)\x00openjdk\x00java\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>[0-9]+[^\x00]+)\x00`),
		Package: "java",
		PURL:    mustPURL("pkg:generic/java@version"),
		// TODO the updates might need to be part of the CPE, like: 1.8.0:update152
		CPEs: singleCPE("cpe:2.3:a:oracle:openjdk:*:*:*:*:*:*:*:*"),
	},
	{
		Class:    "java-binary-ibm",
		FileGlob: "**/java",
		EvidenceMatcher: fileContentsVersionMatcher(
			// [NUL]java[NUL]1.8[NUL][NUL][NUL][NUL]1.8.0-foreman_2022_09_22_15_30-b00[NUL]
			`(?m)\x00java\x00(?P<release>[0-9]+[.0-9]+)\x00{4}(?P<version>[0-9]+[-._a-zA-Z0-9]+)\x00`),
		Package: "java",
		PURL:    mustPURL("pkg:generic/java@version"),
		CPEs:    singleCPE("cpe:2.3:a:ibm:java:*:*:*:*:*:*:*:*"),
	},
	{
		Class:    "java-binary-oracle",
		FileGlob: "**/java",
		EvidenceMatcher: fileContentsVersionMatcher(
			// [NUL]19.0.1+10-21[NUL]
			`(?m)\x00(?P<version>[0-9]+[.0-9]+[+][-0-9]+)\x00`),
		Package: "java",
		PURL:    mustPURL("pkg:generic/java@version"),
		CPEs:    singleCPE("cpe:2.3:a:oracle:jre:*:*:*:*:*:*:*:*"),
	},
	{
		Class:    "nodejs-binary",
		FileGlob: "**/node",
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)node\.js\/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		Package:  "node",
		Language: pkg.JavaScript,
		PURL:     mustPURL("pkg:generic/node@version"),
		CPEs:     singleCPE("cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"),
	},
	{
		Class:    "go-binary-hint",
		FileGlob: "**/VERSION",
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)?)`),
		Package: "go",
		PURL:    mustPURL("pkg:generic/go@version"),
	},
	{
		Class:    "busybox-binary",
		FileGlob: "**/busybox",
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)BusyBox\s+v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		Package: "busybox",
		CPEs:    singleCPE("cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*"),
	},
	{
		Class:    "haproxy-binary",
		FileGlob: "**/haproxy",
		EvidenceMatcher: evidenceMatchers(
			fileContentsVersionMatcher(`(?m)HA-Proxy version (?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
			fileContentsVersionMatcher(`(?m)(?P<version>[0-9]+\.[0-9]+\.[0-9]+)-[0-9a-zA-Z]{7}.+HAProxy version`),
		),
		Package: "haproxy",
		PURL:    mustPURL("pkg:generic/haproxy@version"),
		CPEs:    singleCPE("cpe:2.3:a:haproxy:haproxy:*:*:*:*:*:*:*:*"),
	},
	{
		Class:    "perl-binary",
		FileGlob: "**/perl",
		EvidenceMatcher: fileContentsVersionMatcher(
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
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`),
		Package: "php-fpm",
		PURL:    mustPURL("pkg:generic/php-fpm@version"),
		CPEs:    singleCPE("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"),
	},
	{
		Class:    "php-apache-binary",
		FileGlob: "**/libphp*.so",
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`),
		Package: "libphp",
		PURL:    mustPURL("pkg:generic/php@version"),
		CPEs:    singleCPE("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"),
	},
	{
		Class:    "httpd-binary",
		FileGlob: "**/httpd",
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)Apache\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		Package: "httpd",
		PURL:    mustPURL("pkg:generic/httpd@version"),
		CPEs:    singleCPE("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
	},
	{
		Class:    "memcached-binary",
		FileGlob: "**/memcached",
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)memcached\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		Package: "memcached",
		PURL:    mustPURL("pkg:generic/memcached@version"),
	},
	{
		Class:    "traefik-binary",
		FileGlob: "**/traefik",
		EvidenceMatcher: fileContentsVersionMatcher(
			// [NUL]v1.7.34[NUL]
			// [NUL]2.9.6[NUL]
			`(?m)\x00v?(?P<version>[0-9]+\.[0-9]+\.[0-9]+(-alpha[0-9]|-beta[0-9]|-rc[0-9])?)\x00`),
		Package: "traefik",
		PURL:    mustPURL("pkg:generic/traefik@version"),
	},
	{
		Class:    "postgresql-binary",
		FileGlob: "**/postgres",
		EvidenceMatcher: fileContentsVersionMatcher(
			// [NUL]PostgreSQL 15beta4
			// [NUL]PostgreSQL 15.1
			// [NUL]PostgreSQL 9.6.24
			// ?PostgreSQL 9.5alpha1
			`(?m)(\x00|\?)PostgreSQL (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)?(alpha[0-9]|beta[0-9]|rc[0-9])?)`),
		Package: "postgresql",
		PURL:    mustPURL("pkg:generic/postgresql@version"),
	},
	{
		Class:    "rust-standard-library-linux",
		FileGlob: "**/libstd-????????????????.so",
		EvidenceMatcher: fileContentsVersionMatcher(
			// clang LLVM (rustc version 1.48.0 (7eac88abb 2020-11-16))
			`(?m)(\x00)clang LLVM \(rustc version (?P<version>[0-9]+(\.[0-9]+)?(\.[0-9]+)) \(\w+ \d{4}\-\d{2}\-\d{2}\)`),
		Package: "rust",
		PURL:    mustPURL("pkg:generic/rust@version"),
		CPEs:    singleCPE("cpe:2.3:a:rust-lang:rust:*:*:*:*:*:*:*:*"),
	},
	{
		Class:    "rust-standard-library-macos",
		FileGlob: "**/libstd-????????????????.dylib",
		EvidenceMatcher: fileContentsVersionMatcher(
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
		Class:    "consul-binary",
		FileGlob: "**/consul",
		EvidenceMatcher: fileContentsVersionMatcher(
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
		EvidenceMatcher: fileContentsVersionMatcher(
			// [NUL]nginx version: nginx/1.25.1 - fetches '1.25.1'
			// [NUL]nginx version: openresty/1.21.4.1 - fetches '1.21.4' as this is the nginx version part
			`(?m)(\x00|\?)nginx version: [^\/]+\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(?:\+\d+)?(?:-\d+)?)`,
		),
		Package: "nginx",
		PURL:    mustPURL("pkg:generic/nginx@version"),
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"),
			cpe.Must("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"),
		},
	},
	{
		Class:    "bash-binary",
		FileGlob: "**/bash",
		EvidenceMatcher: fileContentsVersionMatcher(
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
}

// in both binaries and shared libraries, the version pattern is [NUL]3.11.2[NUL]
var pythonVersionTemplate = `(?m)\x00(?P<version>{{ .version }}[-._a-zA-Z0-9]*)\x00`

var libpythonMatcher = fileNameTemplateVersionMatcher(
	`(?:.*/|^)libpython(?P<version>[0-9]+(?:\.[0-9]+)+)[a-z]?\.so.*$`,
	pythonVersionTemplate,
)

var rubyMatcher = fileContentsVersionMatcher(
	// ruby 3.2.1 (2023-02-08 revision 31819e82c8) [x86_64-linux]
	// ruby 2.7.7p221 (2022-11-24 revision 168ec2b1e5) [x86_64-linux]
	`(?m)ruby (?P<version>[0-9]+\.[0-9]+\.[0-9]+(p[0-9]+)?) `)
