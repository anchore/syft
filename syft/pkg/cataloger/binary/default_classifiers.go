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
	},
	{
		Class:    "python-binary-lib",
		FileGlob: "**/libpython*.so*",
		EvidenceMatcher: fileNameTemplateVersionMatcher(
			`(.*/|^)libpython(?P<version>[0-9]+\.[0-9]+).so.*$`,
			`(?m)(?P<version>{{ .version }}\.[0-9]+[-_a-zA-Z0-9]*)`),
		Package: "python",
	},
	{
		Class:    "cpython-source",
		FileGlob: "**/patchlevel.h",
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)#define\s+PY_VERSION\s+"?(?P<version>[0-9\.\-_a-zA-Z]+)"?`),
		Package: "python",
	},
	{
		Class:    "go-binary",
		FileGlob: "**/go",
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)?)\x00`),
		Package: "go",
		CPEs:    singleCPE("cpe:2.3:a:golang:go:*:*:*:*:*:*:*:*"),
	},
	{
		Class:    "java-binary-openjdk",
		FileGlob: "**/java",
		EvidenceMatcher: fileContentsVersionMatcher(
			// [NUL]openjdk[NUL]java[NUL]0.0[NUL]11.0.17+8-LTS[NUL]
			// [NUL]openjdk[NUL]java[NUL]1.8[NUL]1.8.0_352-b08[NUL]
			`(?m)\x00openjdk\x00java\x00(?P<release>[0-9]+[.0-9]*)\x00(?P<version>[0-9]+[^\x00]+)\x00`),
		Package: "java",
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
		CPEs:    singleCPE("cpe:2.3:a:ibm:java:*:*:*:*:*:*:*:*"),
	},
	{
		Class:    "java-binary-oracle",
		FileGlob: "**/java",
		EvidenceMatcher: fileContentsVersionMatcher(
			// [NUL]19.0.1+10-21[NUL]
			`(?m)\x00(?P<version>[0-9]+[.0-9]+[+][-0-9]+)\x00`),
		Package: "java",
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
	},
	{
		Class:    "busybox-binary",
		FileGlob: "**/busybox",
		EvidenceMatcher: fileContentsVersionMatcher(
			`(?m)BusyBox\s+v(?P<version>[0-9]+\.[0-9]+\.[0-9]+)`),
		Package: "busybox",
	},
}
