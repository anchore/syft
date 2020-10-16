package javascript

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
)

// integrity check
var _ common.ParserFn = parseYarnLock

var composedNameExp = regexp.MustCompile("^\"(@{1}[^@]+)")
var simpleNameExp = regexp.MustCompile(`^[a-zA-Z\-]+@`)
var versionExp = regexp.MustCompile(`^\W+(version)\W+`)

func parseYarnLock(_ string, reader io.Reader) ([]pkg.Package, error) {
	packages := make([]pkg.Package, 0)
	fields := make(map[string]string)
	var currentName string

	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimRight(line, "\n")

		// create the entry so that the loop can keep appending versions later
		_, ok := fields[currentName]
		if !ok {
			fields[currentName] = ""
		}

		switch {
		case composedNameExp.MatchString(line):
			name := composedNameExp.FindString(line)
			if len(name) == 0 {
				log.Errorf("unable to parse line: '%s'", line)
			}
			currentName = strings.TrimLeft(name, "\"")
		case simpleNameExp.MatchString(line):
			parts := strings.Split(line, "@")
			currentName = parts[0]
		case versionExp.MatchString(line):
			parts := strings.Split(line, " \"")
			version := parts[len(parts)-1]

			versions, ok := fields[currentName]
			if !ok {
				return nil, fmt.Errorf("no previous key exists, expecting: %s", currentName)
			}

			if strings.Contains(versions, version) {
				// already exists from another dependency declaration
				continue
			}

			// append the version as a string so that we can check on it later
			fields[currentName] = versions + " " + version
			packages = append(packages, pkg.Package{
				Name:     currentName,
				Version:  strings.Trim(version, "\""),
				Language: pkg.JavaScript,
				Type:     pkg.NpmPkg,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to parse yarn.lock file: %w", err)
	}

	return packages, nil
}
