package javascript

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"

	"github.com/anchore/syft/internal"

	"github.com/mitchellh/mapstructure"

	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
)

// integrity check
var _ common.ParserFn = parsePackageLock

// PackageJSON represents a JavaScript package.json file
type PackageJSON struct {
	Version      string            `json:"version"`
	Latest       []string          `json:"latest"`
	Author       Author            `json:"author"`
	License      string            `json:"license"`
	Name         string            `json:"name"`
	Homepage     string            `json:"homepage"`
	Description  string            `json:"description"`
	Dependencies map[string]string `json:"dependencies"`
}

type Author struct {
	Name  string `json:"name" mapstruct:"name"`
	Email string `json:"email" mapstruct:"email"`
	URL   string `json:"url" mapstruct:"url"`
}

// match example: "author": "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)"
// ---> name: "Isaac Z. Schlueter" email: "i@izs.me" url: "http://blog.izs.me"
var authorPattern = regexp.MustCompile(`^\s*(?P<name>[^<(]*)(\s+<(?P<email>.*)>)?(\s\((?P<url>.*)\))?\s*$`)

func (a *Author) UnmarshalJSON(b []byte) error {
	var authorStr string
	var fields map[string]string
	var author Author

	if err := json.Unmarshal(b, &authorStr); err != nil {
		// string parsing did not work, assume a map was given
		// for more information: https://docs.npmjs.com/files/package.json#people-fields-author-contributors
		if err := json.Unmarshal(b, &fields); err != nil {
			return fmt.Errorf("unable to parse package.json author: %w", err)
		}
	} else {
		// parse out "name <email> (url)" into an Author struct
		fields = internal.MatchCaptureGroups(authorPattern, authorStr)
	}

	// translate the map into a structure
	if err := mapstructure.Decode(fields, &author); err != nil {
		return fmt.Errorf("unable to decode package.json author: %w", err)
	}

	*a = author

	return nil
}

func (a *Author) String() string {
	result := a.Name
	if a.Email != "" {
		result += fmt.Sprintf(" <%s>", a.Email)
	}
	if a.URL != "" {
		result += fmt.Sprintf(" (%s)", a.URL)
	}
	return result
}

// parsePackageJson parses a package.json and returns the discovered JavaScript packages.
func parsePackageJSON(_ string, reader io.Reader) ([]pkg.Package, error) {
	packages := make([]pkg.Package, 0)
	dec := json.NewDecoder(reader)

	for {
		var p PackageJSON
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("failed to parse package.json file: %w", err)
		}

		packages = append(packages, pkg.Package{
			Name:     p.Name,
			Version:  p.Version,
			Licenses: []string{p.License},
			Language: pkg.JavaScript,
			Type:     pkg.NpmPkg,
			Metadata: pkg.NpmMetadata{
				Author:   p.Author.String(),
				Homepage: p.Homepage,
			},
		})
	}

	return packages, nil
}
