package javascript

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"slices"
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
	Version         string            `json:"version"`
	Latest          []string          `json:"latest"`
	Author          person            `json:"author"`
	Authors         people            `json:"authors"`
	Contributors    people            `json:"contributors"`
	Maintainers     people            `json:"maintainers"`
	License         json.RawMessage   `json:"license"`
	Licenses        json.RawMessage   `json:"licenses"`
	Name            string            `json:"name"`
	Homepage        string            `json:"homepage"`
	Description     string            `json:"description"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
	Repository      repository        `json:"repository"`
	Private         bool              `json:"private"`
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
	// Composer vendor/<vendor>/<pkg>/package.json files belong to PHP
	// packages that happen to ship a bundled JS manifest. Treating them
	// as independent npm packages leads to false-positive npm CVEs, see
	// anchore/grype#3279. Skip these when a sibling composer.json makes
	// it unambiguous that the vendor tree is composer-managed.
	if isComposerVendoredPackageJSON(resolver, reader.Location.RealPath) {
		return nil, nil, nil
	}

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
		var fields map[string]any
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
	return slices.Contains(filepathSeparator.Split(p, -1), "node_modules")
}

func (p *people) UnmarshalJSON(b []byte) error {
	// Accept either a JSON array of authors, or a single author as a string or
	// object — the latter is used in the wild (e.g. ghost@5.98.1) and dropping
	// the whole package.json on those was https://github.com/anchore/syft/issues/4778.
	var elements []json.RawMessage
	if err := json.Unmarshal(b, &elements); err != nil {
		// not an array — treat the whole payload as a single element
		elements = []json.RawMessage{b}
	}

	auths := make([]person, len(elements))
	for i, e := range elements {
		if err := json.Unmarshal(e, &auths[i]); err != nil {
			return fmt.Errorf("unable to parse package.json author: %w", err)
		}
	}
	*p = auths
	return nil
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

// isComposerVendoredPackageJSON returns true when the given package.json
// path looks like it was installed by Composer (PHP's package manager)
// rather than by npm. Composers install layout is:
//
//	<project>/vendor/<vendor>/<pkg>/...
//
// and a composer.json sits at the project root. When we see a
// package.json under .../vendor/<vendor>/<pkg>/ AND the project root
// carries a composer.json, we treat that package.json as a PHP-owned
// artefact and skip it so its contents do not leak into the npm CVE
// matcher (see anchore/grype#3279).
func isComposerVendoredPackageJSON(resolver file.Resolver, p string) bool {
	if resolver == nil || p == "" {
		return false
	}
	cleaned := path.Clean(p)
	if path.Base(cleaned) != "package.json" {
		return false
	}
	pkgDir := path.Dir(cleaned)               // .../vendor/<vendor>/<pkg>
	vendorNameDir := path.Dir(pkgDir)         // .../vendor/<vendor>
	vendorDir := path.Dir(vendorNameDir)      // .../vendor
	projectRoot := path.Dir(vendorDir)        // ...
	if path.Base(vendorDir) != "vendor" || projectRoot == "" {
		return false
	}
	composerPath := path.Join(projectRoot, "composer.json")
	locs, err := resolver.FilesByPath(composerPath)
	if err != nil || len(locs) == 0 {
		return false
	}
	return true
}
