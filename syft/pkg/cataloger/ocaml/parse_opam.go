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
)

const (
	// opamFileName is the name of a plain opam file, and of the directory it was kept in by an older project layout
	opamFileName       = "opam"
	opamFileSuffix     = ".opam"
	opamLockFileSuffix = ".opam.locked"

	// maxOpamFileSize bounds the opam files read by the OCaml catalogers. The opam parser allocates about 180 bytes per
	// byte of input, so the limit is far above what real files need: opam and lock files are tens of KB (the largest of
	// the 20,000 files of opam-repository is under 40 KB).
	maxOpamFileSize = 1 * intFile.MB
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
	if fileName != opamFileName && hasUsableLockFile(resolver, p+".locked") {
		// the lock file describes this package with exact dependency versions
		return nil, nil, nil
	}

	fields, ok := readOpamFields(reader)
	if !ok {
		return nil, nil, nil
	}

	var name, version string
	if fileName == opamFileName {
		name, version = nameAndVersionFromDir(projectDir(dir), fields)
	} else {
		name, version = strings.TrimSuffix(fileName, opamFileSuffix), fields.Version
	}
	if name == "" {
		log.WithFields("path", p).Trace("unable to determine the opam package name")
		return nil, nil, nil
	}

	return []pkg.Package{newOpamPackage(ctx, opamMetadata(name, version, fields), reader.Location)}, nil, nil
}

// skipDeclaredOpamFile reports whether an opam file is not a declaration of a project's own package: build
// output, opam switch internals (installed packages are cataloged separately), entries of an opam-repository
// checkout, and the copies of opam files that are installed next to libraries.
func skipDeclaredOpamFile(resolver file.Resolver, p string) bool {
	if isBuildOutput(p) || strings.Contains("/"+p, "/.opam-switch/") {
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
	for dir := path.Dir(p); ; dir = path.Dir(dir) {
		if fileExists(resolver, path.Join(dir, ".opam-switch", "switch-state")) {
			return true
		}
		// the root is checked too: it is the switch when the switch itself is scanned
		if dir == "/" || dir == "." || dir == "" {
			return false
		}
	}
}

func isBuildOutput(p string) bool {
	return strings.HasPrefix(p, "_build/") || strings.Contains(p, "/_build/")
}

// projectDir returns the directory a plain `opam` file describes: its own directory, or the parent of an `opam/`
// directory (an older layout).
func projectDir(dir string) string {
	dir = path.Clean(dir)
	if path.Base(dir) == opamFileName {
		dir = path.Dir(dir)
	}
	return dir
}

// archiveDirPattern matches a `<name>-<version>` directory, as unpacked from a source archive (e.g. cmdliner-1.3.0).
var archiveDirPattern = regexp.MustCompile(`^(.+?)-(v?[0-9]+(?:\.[0-9]+)+.*)$`)

// versionPattern matches what a version in a directory name starts with. Versions of opam packages begin with a
// digit, some with a "v".
var versionPattern = regexp.MustCompile(`^v?[0-9]`)

// nameAndVersionFromDir prefers the name and version fields of the file, falling back to the name of the directory
// (a project directory is given as its path), which is `<name>.<version>` (opam package names cannot contain a dot),
// `<name>-<version>` (a source archive) or just the name. A name that ends in digits makes the last two ambiguous
// (bls12-381.0.3.14 or cmdliner-1.3.0); the opam-repository layout, where the directory sits in a directory named
// after the package (bls12-381/bls12-381.0.3.14), settles it for the first.
func nameAndVersionFromDir(dir string, fields opamFields) (string, string) {
	name, version := fields.Name, fields.Version
	if name != "" && version != "" {
		return name, version
	}
	base := path.Base(dir)
	if base == "/" || base == "." {
		// the root of the scan has no usable name
		base = ""
	}
	dirName, dirVersion := splitDirName(base, path.Base(path.Dir(dir)), name)
	if name == "" {
		name = dirName
	} else if dirName != name {
		// the directory is not named after the package, so its version is not the package's
		dirVersion = ""
	}
	if version == "" {
		version = dirVersion
	}
	return name, version
}

// splitDirName splits a directory name into a name and a version. parent is the name of the directory holding it, and
// name the package name given by the opam file, when there is one.
func splitDirName(dir, parent, name string) (string, string) {
	if dir == "" {
		return "", ""
	}
	dotName, dotVersion, dotFound := splitNameVersion(dir)
	if name != "" {
		// the name is known, so only the version has to be found
		for _, sep := range []string{".", "-"} {
			v, found := strings.CutPrefix(dir, name+sep)
			if found && (versionPattern.MatchString(v) || (sep == "." && parent == name)) {
				return name, v
			}
		}
		return dir, ""
	}
	// in the directory of the package, the text after the dot is the version, whatever it is (atomic.base, ...)
	if dotFound && dotName == parent {
		return dotName, dotVersion
	}
	if m := archiveDirPattern.FindStringSubmatch(dir); m != nil {
		return m[1], m[2]
	}
	if dotFound && versionPattern.MatchString(dotVersion) {
		return dotName, dotVersion
	}
	return dir, ""
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

func readOpamFields(reader io.Reader) (opamFields, bool) {
	data, err := readMetadataFileWithLimit(reader, maxOpamFileSize)
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
	data, loc, ok := readFile(resolver, p, maxOpamFileSize)
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

func readFile(resolver file.Resolver, p string, limit int64) ([]byte, file.Location, bool) {
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
	data, err := readMetadataFileWithLimit(rc, limit)
	if err != nil {
		return nil, file.Location{}, false
	}
	return data, locs[0], true
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
