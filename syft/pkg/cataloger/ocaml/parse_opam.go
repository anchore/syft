package ocaml

import (
	"context"
	"errors"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

const (
	// opamFileName is the name of a plain opam file, and of the directory it was kept in by an older project layout
	opamFileName       = "opam"
	opamFileSuffix     = ".opam"
	opamLockFileSuffix = ".opam.locked"

	// maxMetadataFileSize bounds the opam, META and dune-package files read by the OCaml catalogers. These are small
	// text files; the largest dune-package files, which list every installed file, are a few hundred KB.
	maxMetadataFileSize = 16 * intFile.MB
)

var errMetadataFileTooLarge = errors.New("OCaml package metadata file is larger than the max allowed size")

// parseOpamPackage parses a declared opam package definition: a `<name>.opam` file or a plain `opam` file in a
// project. Dependencies are recorded by name only: they are version constraints, not the packages that are used, so
// no relationships are made to packages cataloged elsewhere.
func parseOpamPackage(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	p := reader.Path()
	if skipDeclaredOpamFile(resolver, p) {
		return nil, nil, nil
	}
	dir, fileName := path.Split(p)
	if fileName != opamFileName && fileExists(resolver, p+".locked") {
		// the lock file describes this package with exact dependency versions
		return nil, nil, nil
	}

	fields, ok := readOpamFields(reader)
	if !ok {
		return nil, nil, nil
	}

	var name, version string
	if fileName == opamFileName {
		name, version = nameAndVersionFromDir(projectDirName(dir), fields)
	} else {
		name, version = strings.TrimSuffix(fileName, opamFileSuffix), fields.Version
	}
	if name == "" {
		log.WithFields("path", p).Trace("unable to determine the opam package name")
		return nil, nil, nil
	}

	return []pkg.Package{newOpamPackage(ctx, opamMetadata(name, version, fields), reader.Location)}, nil, nil
}

// parseOpamLockFile parses a `<name>.opam.locked` file (as written by `opam lock`). The project package takes its
// descriptive metadata (license, homepage, ...) from the sibling `<name>.opam` file when present. Relationships are
// resolved within the lock file only, so that packages of other projects or lock files are never linked.
func parseOpamLockFile(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	p := reader.Path()
	if skipDeclaredOpamFile(resolver, p) {
		return nil, nil, nil
	}
	fields, ok := readOpamFields(reader)
	if !ok {
		return nil, nil, nil
	}
	name := strings.TrimSuffix(path.Base(p), opamLockFileSuffix)

	meta := opamMetadata(name, fields.Version, fields)
	licenseLocation := reader.Location
	if project, loc, found := readSiblingOpamFields(resolver, strings.TrimSuffix(p, ".locked")); found {
		if meta.Version == "" {
			meta.Version = project.Version
		}
		meta.Licenses = project.Licenses
		meta.Homepage = project.Homepage
		meta.URL = project.URL
		meta.Checksums = project.Checksums
		licenseLocation = loc
	}

	root := withLicenseLocation(ctx, newOpamPackage(ctx, meta, reader.Location), meta.Licenses, licenseLocation)

	pkgs := append([]pkg.Package{root}, pinnedDependencyPackages(ctx, name, fields, reader.Location)...)
	return pkgs, dependency.Resolve(opamDependencySpecifier, pkgs), nil
}

// skipDeclaredOpamFile reports whether an opam file is not a declaration of a project's own package: build
// output, opam switch internals (installed packages are cataloged separately), entries of an opam-repository
// checkout, and the copies of opam files that are installed next to libraries.
func skipDeclaredOpamFile(resolver file.Resolver, p string) bool {
	if isBuildOutput(p) || strings.Contains(p, "/.opam-switch/") {
		return true
	}
	segments := strings.Split(strings.TrimPrefix(p, "/"), "/")
	if n := len(segments); n >= 4 && segments[n-1] == opamFileName && segments[n-4] == "packages" &&
		strings.HasPrefix(segments[n-2], segments[n-3]+".") {
		return true
	}
	if path.Base(p) == opamFileName {
		dir := path.Dir(p)
		if fileExists(resolver, path.Join(dir, "META")) || fileExists(resolver, path.Join(dir, "dune-package")) {
			return true
		}
	}
	return isInsideOpamSwitch(resolver, p)
}

// isInsideOpamSwitch reports whether the path is within an opam switch, whose packages are cataloged from the
// switch's own records instead.
func isInsideOpamSwitch(resolver file.Resolver, p string) bool {
	for dir := path.Dir(p); dir != "/" && dir != "." && dir != ""; dir = path.Dir(dir) {
		if fileExists(resolver, path.Join(dir, ".opam-switch", "switch-state")) {
			return true
		}
	}
	return false
}

func isBuildOutput(p string) bool {
	return strings.HasPrefix(p, "_build/") || strings.Contains(p, "/_build/")
}

// projectDirName returns the name of the directory a plain `opam` file describes: its own directory, or the parent
// of an `opam/` directory (an older layout). It is empty at the root of the scan, which has no usable name.
func projectDirName(dir string) string {
	dir = path.Clean(dir)
	if path.Base(dir) == opamFileName {
		dir = path.Dir(dir)
	}
	name := path.Base(dir)
	if name == "/" || name == "." {
		return ""
	}
	return name
}

// archiveDirPattern matches a `<name>-<version>` directory, as unpacked from a source archive (e.g. cmdliner-1.3.0).
var archiveDirPattern = regexp.MustCompile(`^(.+?)-(v?[0-9]+(?:\.[0-9]+)+.*)$`)

// nameAndVersionFromDir prefers the name and version fields of the file, falling back to the directory name, which
// is `<name>-<version>` (a source archive), `<name>.<version>` (opam package names cannot contain a dot) or just the
// name.
func nameAndVersionFromDir(dir string, fields opamFields) (string, string) {
	name, version := fields.Name, fields.Version
	if name != "" && version != "" {
		return name, version
	}
	var dirName, dirVersion string
	if m := archiveDirPattern.FindStringSubmatch(dir); m != nil {
		dirName, dirVersion = m[1], m[2]
	} else if n, v, found := splitNameVersion(dir); found {
		dirName, dirVersion = n, v
	} else {
		dirName = dir
	}
	if name == "" {
		name = dirName
	}
	if version == "" {
		version = dirVersion
	}
	return name, version
}

// knownVersion returns "" for values that are build templates rather than versions, such as the %%VERSION%% and
// %%VERSION_NUM%% placeholders that topkg and dune-release substitute when making a release.
func knownVersion(v string) string {
	if strings.Contains(v, "%%") {
		return ""
	}
	return v
}

func splitNameVersion(s string) (string, string, bool) {
	idx := strings.Index(s, ".")
	if idx <= 0 || idx == len(s)-1 {
		return "", "", false
	}
	return s[:idx], s[idx+1:], true
}

func opamMetadata(name, version string, fields opamFields) pkg.OpamPackage {
	return pkg.OpamPackage{
		Name:         name,
		Version:      knownVersion(version),
		Licenses:     fields.Licenses,
		URL:          fields.URL,
		Checksums:    fields.Checksums,
		Homepage:     fields.Homepage,
		Dependencies: dependencyNames(name, fields.Depends),
	}
}

// dependencyNames lists the packages a package depends on, leaving out the ones only needed for development.
func dependencyNames(self string, deps []opamDependency) []string {
	var names []string
	seen := map[string]bool{self: true}
	for _, d := range deps {
		if d.Development || seen[d.Name] {
			continue
		}
		seen[d.Name] = true
		names = append(names, d.Name)
	}
	return names
}

// pinnedDependencyPackages returns a package for each dependency a lock file pins to a version. Pins that are only
// needed to test, document or develop the project are left out, as dev dependencies are for other ecosystems.
func pinnedDependencyPackages(ctx context.Context, self string, fields opamFields, location file.Location) []pkg.Package {
	var pkgs []pkg.Package
	seen := map[string]bool{self: true}
	for _, d := range fields.Depends {
		if d.Version == "" || d.Development || seen[d.Name] {
			continue
		}
		seen[d.Name] = true
		pkgs = append(pkgs, newOpamPackage(ctx, pkg.OpamPackage{Name: d.Name, Version: d.Version}, location))
	}
	return pkgs
}

func readOpamFields(reader io.Reader) (opamFields, bool) {
	data, err := readMetadataFile(reader)
	if err != nil {
		log.WithFields("error", err).Trace("unable to read opam file")
		return opamFields{}, false
	}
	fields, err := parseOpamFields(data)
	if err != nil {
		log.WithFields("error", err).Trace("unable to parse opam file")
		return opamFields{}, false
	}
	return fields, true
}

func readSiblingOpamFields(resolver file.Resolver, p string) (opamFields, file.Location, bool) {
	data, loc, ok := readFile(resolver, p)
	if !ok {
		return opamFields{}, file.Location{}, false
	}
	fields, err := parseOpamFields(data)
	if err != nil {
		return opamFields{}, file.Location{}, false
	}
	return fields, loc, true
}

func fileExists(resolver file.Resolver, p string) bool {
	if resolver == nil {
		return false
	}
	locs, err := resolver.FilesByPath(p)
	return err == nil && len(locs) > 0
}

func readFile(resolver file.Resolver, p string) ([]byte, file.Location, bool) {
	if resolver == nil {
		return nil, file.Location{}, false
	}
	locs, err := resolver.FilesByPath(p)
	if err != nil || len(locs) == 0 {
		return nil, file.Location{}, false
	}
	rc, err := resolver.FileContentsByLocation(locs[0])
	if err != nil {
		return nil, file.Location{}, false
	}
	defer internal.CloseAndLogError(rc, locs[0].RealPath)
	data, err := readMetadataFile(rc)
	if err != nil {
		return nil, file.Location{}, false
	}
	return data, locs[0], true
}

func readMetadataFile(r io.Reader) ([]byte, error) {
	return readMetadataFileWithLimit(r, maxMetadataFileSize)
}

// readMetadataFileWithLimit reads the whole file, failing (rather than truncating) when it is larger than limit.
func readMetadataFileWithLimit(r io.Reader, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errMetadataFileTooLarge
	}
	return data, nil
}
