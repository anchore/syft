package javascript

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// integrity check
var _ generic.Parser = parsePackageLock

// packageLock represents a JavaScript package.lock json file
type packageLock struct {
	Name            string                            `json:"name"`
	Version         string                            `json:"version"`
	LockfileVersion int                               `json:"lockfileVersion"`
	Dependencies    map[string]*packageLockDependency `json:"dependencies"`
	Packages        map[string]*packageLockPackage    `json:"packages"`
	Requires        bool                              `json:"requires"`
}

type packageLockPackage struct {
	Name            string             `json:"name"`
	Version         string             `json:"version"`
	Integrity       string             `json:"integrity"`
	Resolved        string             `json:"resolved"`
	Dependencies    map[string]string  `json:"dependencies"`
	DevDependencies map[string]string  `json:"devDependencies"`
	License         packageLockLicense `json:"license"`
	Dev             bool               `json:"dev"`
	Requires        map[string]string  `json:"requires"`
}

type packageLockDependency struct {
	name         string
	Version      string                            `json:"version"`
	Requires     map[string]string                 `json:"requires"`
	Integrity    string                            `json:"integrity"`
	Resolved     string                            `json:"resolved"`
	Dependencies map[string]*packageLockDependency `json:"dependencies"`
}

// packageLockLicense
type packageLockLicense []string

func parsePackageLockFile(reader file.LocationReadCloser) (packageLock, error) {
	// in the case we find package-lock.json files in the node_modules directories, skip those
	// as the whole purpose of the lock file is for the specific dependencies of the root project
	if pathContainsNodeModulesDirectory(reader.AccessPath()) {
		return packageLock{}, nil
	}
	dec := json.NewDecoder(reader)

	var lock packageLock
	for {
		if err := dec.Decode(&lock); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return packageLock{}, fmt.Errorf("failed to parse package-lock.json file: %w", err)
		}
	}
	return lock, nil
}

// parsePackageLock parses a package-lock.json and returns the discovered JavaScript packages.
func parsePackageLock(resolver file.Resolver, e *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	readers := []file.LocationReadCloser{reader}
	pkgs, _, err := parseJavascript(resolver, e, readers)
	if err != nil {
		return nil, nil, err
	}
	return pkgs, nil, nil
}

func (licenses *packageLockLicense) UnmarshalJSON(data []byte) (err error) {
	// The license field could be either a string or an array.

	// 1. An array
	var arr []string
	if err := json.Unmarshal(data, &arr); err == nil {
		*licenses = arr
		return nil
	}

	// 2. A string
	var str string
	if err = json.Unmarshal(data, &str); err == nil {
		*licenses = make([]string, 1)
		(*licenses)[0] = str
		return nil
	}

	// debug the content we did not expect
	if len(data) > 0 {
		log.WithFields("license", string(data)).Debug("Unable to parse the following `license` value in package-lock.json")
	}

	// 3. Unexpected
	// In case we are unable to parse the license field,
	// i.e if we have not covered the full specification,
	// we do not want to throw an error, instead assign nil.
	return nil
}

func getNameFromPath(path string) string {
	parts := strings.Split(path, "node_modules/")
	return parts[len(parts)-1]
}
