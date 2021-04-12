package javascript

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/syft/internal"

	"github.com/mitchellh/mapstructure"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parsePackageLock

// PackageJSON represents a JavaScript package.json file
type PackageJSON struct {
	Version      string            `json:"version"`
	Latest       []string          `json:"latest"`
	Author       Author            `json:"author"`
	License      json.RawMessage   `json:"license"`
	Licenses     []license         `json:"licenses"`
	Name         string            `json:"name"`
	Homepage     string            `json:"homepage"`
	Description  string            `json:"description"`
	Dependencies map[string]string `json:"dependencies"`
	Repository   Repository        `json:"repository"`
}

type Author struct {
	Name  string `json:"name" mapstruct:"name"`
	Email string `json:"email" mapstruct:"email"`
	URL   string `json:"url" mapstruct:"url"`
}

type Repository struct {
	Type string `json:"type" mapstructure:"type"`
	URL  string `json:"url" mapstructure:"url"`
}

// match example: "author": "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)"
// ---> name: "Isaac Z. Schlueter" email: "i@izs.me" url: "http://blog.izs.me"
var authorPattern = regexp.MustCompile(`^\s*(?P<name>[^<(]*)(\s+<(?P<email>.*)>)?(\s\((?P<url>.*)\))?\s*$`)

// Exports Author.UnmarshalJSON interface to help normalize the json structure.
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
		fields = internal.MatchNamedCaptureGroups(authorPattern, authorStr)
	}

	// translate the map into a structure
	if err := mapstructure.Decode(fields, &author); err != nil {
		return fmt.Errorf("unable to decode package.json author: %w", err)
	}

	*a = author

	return nil
}

func (a *Author) AuthorString() string {
	result := a.Name
	if a.Email != "" {
		result += fmt.Sprintf(" <%s>", a.Email)
	}
	if a.URL != "" {
		result += fmt.Sprintf(" (%s)", a.URL)
	}
	return result
}

func (r *Repository) UnmarshalJSON(b []byte) error {
	var repositoryStr string
	var fields map[string]string
	var repository Repository

	if err := json.Unmarshal(b, &repositoryStr); err != nil {
		// string parsing did not work, assume a map was given
		// for more information: https://docs.npmjs.com/files/package.json#people-fields-author-contributors
		if err := json.Unmarshal(b, &fields); err != nil {
			return fmt.Errorf("unable to parse package.json author: %w", err)
		}
		// translate the map into a structure
		if err := mapstructure.Decode(fields, &repository); err != nil {
			return fmt.Errorf("unable to decode package.json author: %w", err)
		}

		*r = repository
	} else {
		r.URL = repositoryStr
	}

	return nil
}

type license struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

func licenseFromJSON(b []byte) (string, error) {
	// first try as string
	var licenseString string
	err := json.Unmarshal(b, &licenseString)
	if err == nil {
		return licenseString, nil
	}

	// then try as object (this format is deprecated)
	var licenseObject license
	err = json.Unmarshal(b, &licenseObject)
	if err == nil {
		return licenseObject.Type, nil
	}

	return "", errors.New("unable to unmarshal license field as either string or object")
}

func licensesFromJSON(p PackageJSON) ([]string, error) {
	if p.License == nil && p.Licenses == nil {
		// This package.json doesn't specify any licenses whatsoever
		return []string{}, nil
	}

	singleLicense, err := licenseFromJSON(p.License)
	if err == nil {
		return []string{singleLicense}, nil
	}

	// The "licenses" field is deprecated. It should be inspected as a last resort.
	if p.Licenses != nil {
		mapLicenses := func(licenses []license) []string {
			mappedLicenses := make([]string, len(licenses))
			for i, l := range licenses {
				mappedLicenses[i] = l.Type
			}
			return mappedLicenses
		}

		return mapLicenses(p.Licenses), nil
	}

	return nil, fmt.Errorf("unable to parse license field: %w", err)
}

// parsePackageJSON parses a package.json and returns the discovered JavaScript packages.
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

		if !p.hasNameAndVersionValues() {
			log.Debug("encountered package.json file without a name and/or version field, ignoring this file")
			return nil, nil
		}

		licenses, err := licensesFromJSON(p)
		if err != nil {
			return nil, fmt.Errorf("failed to parse package.json file: %w", err)
		}

		packages = append(packages, pkg.Package{
			Name:         p.Name,
			Version:      p.Version,
			Licenses:     licenses,
			Language:     pkg.JavaScript,
			Type:         pkg.NpmPkg,
			MetadataType: pkg.NpmPackageJSONMetadataType,
			Metadata: pkg.NpmPackageJSONMetadata{
				Author:   p.Author.AuthorString(),
				Homepage: p.Homepage,
				URL:      p.Repository.URL,
				Licenses: licenses,
			},
		})
	}

	return packages, nil
}

func (p PackageJSON) hasNameAndVersionValues() bool {
	return p.Name != "" && p.Version != ""
}
