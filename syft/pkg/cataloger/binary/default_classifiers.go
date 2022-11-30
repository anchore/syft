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
			`(?m)go(?P<version>[0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)?)`),
		Package: "go",
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
