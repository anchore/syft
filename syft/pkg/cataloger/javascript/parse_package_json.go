package javascript

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/go-viper/mapstructure/v2"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// integrity check
var _ generic.Parser = parsePackageJSON

// packageJSON represents a JavaScript package.json file
type packageJSON struct {
	Version      string            `json:"version"`
	Latest       []string          `json:"latest"`
	Author       person            `json:"author"`
	Authors      people            `json:"authors"`
	Contributors people            `json:"contributors"`
	Maintainers  people            `json:"maintainers"`
	License      json.RawMessage   `json:"license"`
	Licenses     json.RawMessage   `json:"licenses"`
	Name         string            `json:"name"`
	Homepage     string            `json:"homepage"`
	Description  string            `json:"description"`
	Dependencies map[string]string `json:"dependencies"`
	Repository   repository        `json:"repository"`
	Private      bool              `json:"private"`
}

type person struct {
	Name  string `json:"name" mapstructure:"name"`
	Email string `json:"email" mapstructure:"email"`
	URL   string `json:"url" mapstructure:"url"`
}

type people []person

type repository struct {
	Type string `json:"type" mapstructure:"type"`
	URL  string `json:"url" mapstructure:"url"`
}

// match example: "author": "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)"
// ---> name: "Isaac Z. Schlueter" email: "i@izs.me" url: "http://blog.izs.me"
var authorPattern = regexp.MustCompile(`^\s*(?P<name>[^<(]*)(\s+<(?P<email>.*)>)?(\s\((?P<url>.*)\))?\s*$`)

// parsePackageJSON parses a package.json and returns the discovered JavaScript packages.
func parsePackageJSON(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	dec := json.NewDecoder(reader)

	for {
		var p packageJSON
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse package.json file: %w", err)
		}

		// always create a package, regardless of having a valid name and/or version,
		// a compliance filter later will remove these packages based on compliance rules
		pkgs = append(
			pkgs,
			newPackageJSONPackage(ctx, resolver, p, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		)
	}

	pkg.Sort(pkgs)

	return pkgs, nil, nil
}

func (p *person) UnmarshalJSON(b []byte) error {
	var authorStr string
	var auth person

	if err := json.Unmarshal(b, &authorStr); err == nil {
		// successfully parsed as a string, now parse that string into fields
		fields := internal.MatchNamedCaptureGroups(authorPattern, authorStr)
		if err := mapstructure.Decode(fields, &auth); err != nil {
			return fmt.Errorf("unable to decode package.json author: %w", err)
		}
	} else {
		// it's a map that may contain fields of various data types (not just strings)
		var fields map[string]interface{}
		if err := json.Unmarshal(b, &fields); err != nil {
			return fmt.Errorf("unable to parse package.json author: %w", err)
		}
		if err := mapstructure.Decode(fields, &auth); err != nil {
			return fmt.Errorf("unable to decode package.json author: %w", err)
		}
	}

	*p = auth

	return nil
}

func (p *person) AuthorString() string {
	result := p.Name
	if p.Email != "" {
		result += fmt.Sprintf(" <%s>", p.Email)
	}
	if p.URL != "" {
		result += fmt.Sprintf(" (%s)", p.URL)
	}
	return result
}

func (r *repository) UnmarshalJSON(b []byte) error {
	var repositoryStr string
	var fields map[string]string
	var repo repository

	if err := json.Unmarshal(b, &repositoryStr); err != nil {
		// string parsing did not work, assume a map was given
		// for more information: https://docs.npmjs.com/files/package.json#people-fields-author-contributors
		if err := json.Unmarshal(b, &fields); err != nil {
			return fmt.Errorf("unable to parse package.json author: %w", err)
		}
		// translate the map into a structure
		if err := mapstructure.Decode(fields, &repo); err != nil {
			return fmt.Errorf("unable to decode package.json author: %w", err)
		}

		*r = repo
	} else {
		r.URL = repositoryStr
	}

	return nil
}

type npmPackageLicense struct {
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
	var licenseObject npmPackageLicense
	err = json.Unmarshal(b, &licenseObject)
	if err == nil {
		return licenseObject.Type, nil
	}

	return "", errors.New("unable to unmarshal license field as either string or object")
}

func (p packageJSON) licensesFromJSON() ([]string, error) {
	if p.License == nil && p.Licenses == nil {
		// This package.json doesn't specify any licenses whatsoever
		return []string{}, nil
	}

	singleLicense, err := licenseFromJSON(p.License)
	if err == nil {
		return []string{singleLicense}, nil
	}

	multiLicense, err := licensesFromJSON(p.Licenses)

	// The "licenses" field is deprecated. It should be inspected as a last resort.
	if multiLicense != nil && err == nil {
		mapLicenses := func(licenses []npmPackageLicense) []string {
			mappedLicenses := make([]string, len(licenses))
			for i, l := range licenses {
				mappedLicenses[i] = l.Type
			}
			return mappedLicenses
		}

		return mapLicenses(multiLicense), nil
	}

	return nil, err
}

func licensesFromJSON(b []byte) ([]npmPackageLicense, error) {
	var licenseObject []npmPackageLicense
	err := json.Unmarshal(b, &licenseObject)
	if err == nil {
		return licenseObject, nil
	}

	return nil, errors.New("unmarshal failed")
}

// this supports both windows and unix paths
var filepathSeparator = regexp.MustCompile(`[\\/]`)

func pathContainsNodeModulesDirectory(p string) bool {
	for _, subPath := range filepathSeparator.Split(p, -1) {
		if subPath == "node_modules" {
			return true
		}
	}
	return false
}

func (p *people) UnmarshalJSON(b []byte) error {
	// Try to unmarshal as an array of strings
	var authorStrings []string
	if err := json.Unmarshal(b, &authorStrings); err == nil {
		// Successfully parsed as an array of strings
		auths := make([]person, len(authorStrings))
		for i, authorStr := range authorStrings {
			// Parse each string into author fields
			fields := internal.MatchNamedCaptureGroups(authorPattern, authorStr)
			var auth person
			if err := mapstructure.Decode(fields, &auth); err != nil {
				return fmt.Errorf("unable to decode package.json author: %w", err)
			}
			// Trim whitespace from name if it was parsed
			if auth.Name != "" {
				auth.Name = strings.TrimSpace(auth.Name)
			}
			auths[i] = auth
		}
		*p = auths
		return nil
	}

	// Try to unmarshal as an array of objects
	var authorObjs []map[string]interface{}
	if err := json.Unmarshal(b, &authorObjs); err == nil {
		// Successfully parsed as an array of objects
		auths := make([]person, len(authorObjs))
		for i, fields := range authorObjs {
			var auth person
			if err := mapstructure.Decode(fields, &auth); err != nil {
				return fmt.Errorf("unable to decode package.json author object: %w", err)
			}
			auths[i] = auth
		}
		*p = auths
		return nil
	}

	// If we get here, it means neither format matched
	return fmt.Errorf("unable to parse package.json authors field: expected array of strings or array of objects")
}

func (p people) String() string {
	if len(p) == 0 {
		return ""
	}

	authorStrings := make([]string, len(p))
	for i, auth := range p {
		authorStrings[i] = auth.AuthorString()
	}
	return strings.Join(authorStrings, ", ")
}
