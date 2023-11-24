package filter

import "strings"

func filterFunc(strFunc func(string, string) bool, args ...string) func(string) bool {
	return func(filename string) bool {
		for _, suffix := range args {
			if strFunc(filename, suffix) {
				return true
			}
		}
		return false
	}
}

var (
	JavaScriptYarnLock    = filterFunc(strings.HasSuffix, "yarn.lock")
	JavaScriptPackageJSON = func(filename string) bool {
		return strings.HasSuffix(filename, "package.json")
	}
	JavaScriptPackageLock = filterFunc(strings.HasSuffix, "package-lock.json")
	JavaScriptPmpmLock    = filterFunc(strings.HasSuffix, "pnpm-lock.yaml")
)
