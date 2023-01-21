package binary

import "github.com/anchore/syft/syft/pkg"

var defaultClassifiers = []classifier{
	{
		Class:    "python-binary",
		FileGlob: "**/python*",
		EvidenceMatcher: fileNameTemplateVersionMatcher(
			`(.*/|^)python(?P<version>[0-9]+\.[0-9]+)$`,
			`(?m)(?P<version>{{ .version }}\.[0-9]+[-_a-zA-Z0-9]*)`),
		Package: "python",
		PURL:    mustPURL("pkg:generic/python@version"),
	},
	{
		Class:    "python-binary-lib",
		FileGlob: "**/libpython*.so*",
		EvidenceMatcher: fileNameTemplateVersionMatcher(
			`(.*/|^)libpython(?P<version>[0-9]+\.[0-9]+).so.*$`,
			`(?m)(?P<version>{{ .version }}\.[0-9]+[-_a-zA-Z0-9]*)`),
		Package: "python",
		PURL:    mustPURL("pkg:generic/python@version"),
	},
	{
		Class:    "cpython-source",
		FileGlob: "**/patchlevel.h",
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)#define\s+PY_VERSION\s+"?(?P<version>[0-9\.\-_a-zA-Z]+)"?`),
		Package: "python",
		PURL:    mustPURL("pkg:generic/python@version"),
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
}
