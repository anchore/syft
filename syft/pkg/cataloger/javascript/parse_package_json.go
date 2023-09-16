package javascript

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/mitchellh/mapstructure"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript/key"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript/model"
)

// integrity check
var _ generic.Parser = parsePackageJSON

type packageJSON struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Author               author            `json:"author"`
	License              json.RawMessage   `json:"license"`
	Licenses             json.RawMessage   `json:"licenses"`
	Homepage             string            `json:"homepage"`
	Private              bool              `json:"private"`
	Description          string            `json:"description"`
	Develop              bool              `json:"dev"` // lock v3
	Repository           repository        `json:"repository"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	PeerDependenciesMeta map[string]struct {
		Optional bool `json:"optional"`
	} `json:"peerDependenciesMeta"`
	File string `json:"-"`
}

type author struct {
	Name  string `json:"name" mapstruct:"name"`
	Email string `json:"email" mapstruct:"email"`
	URL   string `json:"url" mapstruct:"url"`
}

type repository struct {
	Type string `json:"type" mapstructure:"type"`
	URL  string `json:"url" mapstructure:"url"`
}

// match example: "author": "Isaac Z. Schlueter <i@izs.me> (http://blog.izs.me)"
// ---> name: "Isaac Z. Schlueter" email: "i@izs.me" url: "http://blog.izs.me"
var authorPattern = regexp.MustCompile(`^\s*(?P<name>[^<(]*)(\s+<(?P<email>.*)>)?(\s\((?P<url>.*)\))?\s*$`)

func parsePackageJSON(resolver file.Resolver, e *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	readers := []file.LocationReadCloser{reader}
	pkgs, _, err := parseJavascript(resolver, e, readers)
	if err != nil {
		return nil, nil, err
	}
	return pkgs, nil, nil
}

// parsePackageJSON parses a package.json and returns the discovered JavaScript packages.
func parsePackageJSONFile(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) (*packageJSON, error) {
	var js *packageJSON
	decoder := json.NewDecoder(reader)
	err := decoder.Decode(&js)
	if err != nil {
		return nil, err
	}

	return js, nil
}

func handleNpmV1NameVersionAlias(lockDepVersion string) (n, v string) {
	const aliasPrefixPackageLockV1 = "npm:"

	// Handles type aliases https://github.com/npm/rfcs/blob/main/implemented/0001-package-aliases.md
	if strings.HasPrefix(lockDepVersion, aliasPrefixPackageLockV1) {
		// this is an alias.
		// `"version": "npm:canonical-name@X.Y.Z"`
		canonicalPackageAndVersion := lockDepVersion[len(aliasPrefixPackageLockV1):]
		versionSeparator := strings.LastIndex(canonicalPackageAndVersion, "@")

		n = canonicalPackageAndVersion[:versionSeparator]
		v = canonicalPackageAndVersion[versionSeparator+1:]
	}
	return n, v
}

func pkgWithLockDepTree(pkgjson *packageJSON, pkglock *packageLock, root *model.DepGraphNode) *model.DepGraphNode {
	if pkglock.LockfileVersion == 3 || pkglock.LockfileVersion == 2 {
		return parsePackageJSONWithLockV2(pkgjson, pkglock, root)
	}
	depNameMap := map[string]*model.DepGraphNode{}
	_dep := _depSet().LoadOrStore

	// record dependencies
	for name, lockDep := range pkglock.Dependencies {
		lockDep.name = name
		pName, pVersion := handleNpmV1NameVersionAlias(lockDep.Version)
		if pName == "" && pVersion == "" {
			pName = name
			pVersion = lockDep.Version
		}
		dep := _dep(
			pName,
			pVersion,
			lockDep.Integrity,
			lockDep.Resolved,
			"",
		)
		depNameMap[name] = dep
	}

	// build dependency tree
	for name, lockDep := range pkglock.Dependencies {
		lockDep.name = name
		q := []*packageLockDependency{lockDep}
		for len(q) > 0 {
			n := q[0]
			q = q[1:]

			pName, pVersion := handleNpmV1NameVersionAlias(lockDep.Version)
			if pName == "" && pVersion == "" {
				pName = name
				pVersion = lockDep.Version
			}
			dep := _dep(
				pName,
				pVersion,
				n.Integrity,
				n.Resolved,
				"",
			)
			for name, sub := range n.Dependencies {
				sub.name = name
				q = append(q, sub)
				dep.AppendChild(_dep(
					name,
					sub.Version,
					sub.Integrity,
					sub.Resolved,
					"",
				))
			}
			for name := range n.Requires {
				dep.AppendChild(depNameMap[name])
			}
			root.AppendChild(dep)
		}
	}

	if pkgjson != nil {
		for name := range pkgjson.Dependencies {
			root.AppendChild(depNameMap[name])
		}
	}

	return root
}

func convertToPkgAndRelationships(resolver file.Resolver, location file.Location, root *model.DepGraphNode) ([]pkg.Package, []artifact.Relationship) {
	var packages []pkg.Package
	var relationships []artifact.Relationship
	pkgSet := map[string]bool{}

	processNode := func(parent, node *model.DepGraphNode) bool {
		p := finalizeLockPkg(
			resolver,
			location,
			pkg.Package{
				Name:         node.Name,
				Version:      node.Version,
				Locations:    file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
				PURL:         packageURL(node.Name, node.Version),
				Language:     pkg.JavaScript,
				Licenses:     pkg.NewLicenseSet(pkg.NewLicensesFromLocation(location, node.Licenses...)...),
				Type:         pkg.NpmPkg,
				MetadataType: pkg.NpmPackageLockJSONMetadataType,
				Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: node.Resolved, Integrity: node.Integrity},
			},
		)

		if !pkgSet[key.NpmPackageKey(p.Name, p.Version)] {
			packages = append(packages, p)
			pkgSet[key.NpmPackageKey(p.Name, p.Version)] = true
		}

		if parent != nil {
			parentPkg := finalizeLockPkg(
				resolver,
				location,
				pkg.Package{
					Name:         parent.Name,
					Version:      parent.Version,
					Locations:    file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
					PURL:         packageURL(parent.Name, parent.Version),
					Language:     pkg.JavaScript,
					Licenses:     pkg.NewLicenseSet(pkg.NewLicensesFromLocation(location, node.Licenses...)...),
					Type:         pkg.NpmPkg,
					MetadataType: pkg.NpmPackageLockJSONMetadataType,
					Metadata:     pkg.NpmPackageLockJSONMetadata{Resolved: parent.Resolved, Integrity: parent.Integrity},
				})
			rel := artifact.Relationship{
				From: parentPkg,
				To:   p,
				Type: artifact.DependencyOfRelationship,
			}
			relationships = append(relationships, rel)
		}
		return true
	}
	root.ForEachPath(processNode)
	return packages, relationships
}

func parsePackageJSONWithLock(resolver file.Resolver, pkgjson *packageJSON, pkglock *packageLock, indexLocation file.Location) ([]pkg.Package, []artifact.Relationship) {
	if pkgjson != nil {
		if !pkgjson.hasNameAndVersionValues() {
			log.Debugf("encountered package.json file without a name and/or version field, ignoring (path=%q)", indexLocation.AccessPath())
			return nil, nil
		}
	}

	if pkglock == nil {
		rootPkg := newPackageJSONRootPackage(*pkgjson, indexLocation)
		return []pkg.Package{rootPkg}, nil
	}

	var root *model.DepGraphNode
	if pkgjson != nil {
		root = &model.DepGraphNode{Name: pkgjson.Name, Version: pkgjson.Version, Path: pkgjson.File}
	} else {
		if pkglock.Name == "" {
			name := rootNameFromPath(indexLocation)
			root = &model.DepGraphNode{
				Name:    name,
				Version: "0.0.0",
				Path:    indexLocation.RealPath,
			}
		} else {
			root = &model.DepGraphNode{
				Name:    pkglock.Name,
				Version: pkglock.Version,
				Path:    indexLocation.RealPath,
			}
		}
	}

	pkgRoot := pkgWithLockDepTree(pkgjson, pkglock, root)
	pkgs, rels := convertToPkgAndRelationships(
		resolver,
		indexLocation,
		pkgRoot,
	)
	return pkgs, rels
}

func parsePackageJSONWithLockV2(pkgjson *packageJSON, pkglock *packageLock, root *model.DepGraphNode) *model.DepGraphNode {
	if pkglock.LockfileVersion != 3 && pkglock.LockfileVersion != 2 {
		return nil
	}

	depNameMap := map[string]*model.DepGraphNode{}
	_dep := _depSet().LoadOrStore

	for name, lockDep := range pkglock.Packages {
		// root pkg
		if name == "" {
			root.Licenses = lockDep.License
			continue
		}

		if lockDep.Dev {
			continue
		}

		n := getNameFromPath(name)
		dep := _dep(
			n,
			lockDep.Version,
			lockDep.Integrity,
			lockDep.Resolved,
			strings.Join(lockDep.License, ","),
		)
		// need to store both names
		depNameMap[name] = dep
		depNameMap[n] = dep
	}

	for name, lockDep := range pkglock.Packages {
		// root pkg
		if name == "" {
			continue
		}
		dep := depNameMap[name]
		for childName := range lockDep.Dependencies {
			if childDep, ok := depNameMap[childName]; ok {
				dep.AppendChild(childDep)
			}
		}
		root.AppendChild(dep)
	}

	// setup root deps
	if pkgjson != nil {
		for name := range pkgjson.Dependencies {
			root.AppendChild(depNameMap[name])
		}
	}

	return root
}

func (a *author) UnmarshalJSON(b []byte) error {
	var authorStr string
	var fields map[string]string
	var auth author

	if err := json.Unmarshal(b, &authorStr); err != nil {
		// string parsing did not work, assume a map was given
		// for more information: https://docs.npmjs.com/files/package.json#people-fields-author-contributors
		if err := json.Unmarshal(b, &fields); err != nil {
			return fmt.Errorf("unable to parse package.json author: %w", err)
		}
	} else {
		// parse out "name <email> (url)" into an author struct
		fields = internal.MatchNamedCaptureGroups(authorPattern, authorStr)
	}

	// translate the map into a structure
	if err := mapstructure.Decode(fields, &auth); err != nil {
		return fmt.Errorf("unable to decode package.json author: %w", err)
	}

	*a = auth

	return nil
}

func (a *author) AuthorString() string {
	result := a.Name
	if a.Email != "" {
		result += fmt.Sprintf(" <%s>", a.Email)
	}
	if a.URL != "" {
		result += fmt.Sprintf(" (%s)", a.URL)
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

func (p packageJSON) hasNameAndVersionValues() bool {
	return p.Name != "" && p.Version != ""
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
