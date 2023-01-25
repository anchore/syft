package binary

import (
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var defaultClassifiers = []classifier{
	{
		Class:         "python-binary",
		SearchRequest: generic.NewSearch().ByBasenameGlob("python*").Request(),
		EvidenceMatcher: fileNameTemplateVersionMatcher(
			`(.*/|^)python(?P<version>[0-9]+\.[0-9]+)$`,
			`(?m)(?P<version>{{ .version }}\.[0-9]+[-_a-zA-Z0-9]*)`),
		Package: "python",
		PURL:    mustPURL("pkg:generic/python@version"),
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:python_software_foundation:python:*:*:*:*:*:*:*:*"),
			cpe.Must("cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"),
		},
	},
	{
		Class:         "python-binary-lib",
		SearchRequest: generic.NewSearch().ByBasenameGlob("libpython*.so*").Request(),
		EvidenceMatcher: fileNameTemplateVersionMatcher(
			`(.*/|^)libpython(?P<version>[0-9]+\.[0-9]+).so.*$`,
			`(?m)(?P<version>{{ .version }}\.[0-9]+[-_a-zA-Z0-9]*)`),
		Package: "python",
		PURL:    mustPURL("pkg:generic/python@version"),
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:python_software_foundation:python:*:*:*:*:*:*:*:*"),
			cpe.Must("cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"),
		},
	},
	{
		Class:         "cpython-source",
		SearchRequest: generic.NewSearch().ByBasename("patchlevel.h").Request(),
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)#define\s+PY_VERSION\s+"?(?P<version>[0-9\.\-_a-zA-Z]+)"?`),
		Package: "python",
		PURL:    mustPURL("pkg:generic/python@version"),
		CPEs: []cpe.CPE{
			cpe.Must("cpe:2.3:a:python_software_foundation:python:*:*:*:*:*:*:*:*"),
			cpe.Must("cpe:2.3:a:python:python:*:*:*:*:*:*:*:*"),
		},
	},
	{
		Class:         "go-binary",
		SearchRequest: generic.NewSearch().ByBasename("go").Request(),
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)?)\x00`),
		Package: "go",
		PURL:    mustPURL("pkg:generic/go@version"),
		CPEs:    singleCPE("cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*"),
	},
	{
		Class:         "redis-binary",
		SearchRequest: generic.NewSearch().ByBasename("redis-server").Request(),
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?s)payload %5.*(?P<version>\d.\d\.\d\d*?)[a-z0-9]{12}-[0-9]{19}`),
		Package: "redis",
		PURL:    mustPURL("pkg:generic/redis@version"),
		CPEs:    singleCPE("cpe:2.3:a:redislabs:redis:*:*:*:*:*:*:*:*"),
	},
	{
		Class:         "java-binary-openjdk",
		SearchRequest: generic.NewSearch().ByBasename("java").Request(),
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
		Class:         "java-binary-ibm",
		SearchRequest: generic.NewSearch().ByBasename("java").Request(),
		EvidenceMatcher: fileContentsVersionMatcher(
			// [NUL]java[NUL]1.8[NUL][NUL][NUL][NUL]1.8.0-foreman_2022_09_22_15_30-b00[NUL]
			`(?m)\x00java\x00(?P<release>[0-9]+[.0-9]+)\x00{4}(?P<version>[0-9]+[-._a-zA-Z0-9]+)\x00`),
		Package: "java",
		PURL:    mustPURL("pkg:generic/java@version"),
		CPEs:    singleCPE("cpe:2.3:a:ibm:java:*:*:*:*:*:*:*:*"),
	},
	{
		Class:         "java-binary-oracle",
		SearchRequest: generic.NewSearch().ByBasename("java").Request(),
		EvidenceMatcher: fileContentsVersionMatcher(
			// [NUL]19.0.1+10-21[NUL]
			`(?m)\x00(?P<version>[0-9]+[.0-9]+[+][-0-9]+)\x00`),
		Package: "java",
		PURL:    mustPURL("pkg:generic/java@version"),
		CPEs:    singleCPE("cpe:2.3:a:oracle:jre:*:*:*:*:*:*:*:*"),
	},
	{
		Class:         "nodejs-binary",
		SearchRequest: generic.NewSearch().ByBasename("node").Request(),
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)node\.js\/v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		Package:  "node",
		Language: pkg.JavaScript,
		PURL:     mustPURL("pkg:generic/node@version"),
		CPEs:     singleCPE("cpe:2.3:a:nodejs:node.js:*:*:*:*:*:*:*:*"),
	},
	{
		Class:         "go-binary-hint",
		SearchRequest: generic.NewSearch().ByBasename("VERSION").Request(),
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)?)`),
		Package: "go",
		PURL:    mustPURL("pkg:generic/go@version"),
	},
	{
		Class:         "busybox-binary",
		SearchRequest: generic.NewSearch().ByBasename("busybox").Request(),
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)BusyBox\s+v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		Package: "busybox",
		CPEs:    singleCPE("cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*"),
	},
	{
		Class:         "php-cli-binary",
		SearchRequest: generic.NewSearch().ByBasenameGlob("php*").Request(),
		EvidenceMatcher: fileNameTemplateVersionMatcher(
			`(.*/|^)php[0-9]*$`,
			`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`),
		Package: "php-cli",
		PURL:    mustPURL("pkg:generic/php-cli@version"),
		CPEs:    singleCPE("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"),
	},
	{
		Class:         "php-fpm-binary",
		SearchRequest: generic.NewSearch().ByBasenameGlob("php-fpm*").Request(),
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`),
		Package: "php-fpm",
		PURL:    mustPURL("pkg:generic/php-fpm@version"),
		CPEs:    singleCPE("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"),
	},
	{
		Class:         "php-apache-binary",
		SearchRequest: generic.NewSearch().ByBasenameGlob("libphp*.so").Request(),
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)X-Powered-By: PHP\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+(beta[0-9]+|alpha[0-9]+|RC[0-9]+)?)`),
		Package: "libphp",
		PURL:    mustPURL("pkg:generic/php@version"),
		CPEs:    singleCPE("cpe:2.3:a:php:php:*:*:*:*:*:*:*:*"),
	},
	{
		Class:         "httpd-binary",
		SearchRequest: generic.NewSearch().ByBasename("httpd").Request(),
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)Apache\/(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		Package: "httpd",
		PURL:    mustPURL("pkg:generic/httpd@version"),
		CPEs:    singleCPE("cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"),
	},
	{
		Class:         "memcached-binary",
		SearchRequest: generic.NewSearch().ByBasename("memcached").Request(),
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)memcached\s(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		Package: "memcached",
		PURL:    mustPURL("pkg:generic/memcached@version"),
	},
}
