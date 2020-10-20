package python

import (
	"bufio"
	"io"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
)

// integrity check
var _ common.ParserFn = parseSetup

// match examples:
//		'pathlib3==2.2.0;python_version<"3.6"'  --> match(name=pathlib3 version=2.2.0)
//		 "mypy==v0.770",                        --> match(name=mypy version=v0.770)
//		" mypy2 == v0.770", ' mypy3== v0.770',  --> match(name=mypy2 version=v0.770), match(name=mypy3, version=v0.770)
var pinnedDependency = regexp.MustCompile(`['"]\W?(\w+\W?==\W?[\w\.]*)`)

func parseSetup(_ string, reader io.Reader) ([]pkg.Package, error) {
	packages := make([]pkg.Package, 0)

	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimRight(line, "\n")

		for _, match := range pinnedDependency.FindAllString(line, -1) {
			parts := strings.Split(match, "==")
			if len(parts) != 2 {
				continue
			}
			name := strings.Trim(parts[0], "'\"")
			name = strings.TrimSpace(name)

			version := strings.TrimSpace(parts[len(parts)-1])
			packages = append(packages, pkg.Package{
				Name:     strings.Trim(name, "'\""),
				Version:  strings.Trim(version, "'\""),
				Language: pkg.Python,
				Type:     pkg.PythonPkg,
			})
		}
	}

	return packages, nil
}
