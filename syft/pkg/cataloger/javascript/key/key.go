package key

import "fmt"

func NpmPackageKey(name, version string) string {
	return fmt.Sprintf("%s:%s", name, version)
}
