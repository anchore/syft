package ocaml

import (
	"bufio"
	"bytes"
	"context"
	"path"
	"regexp"
	"strings"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// maxLibraryFileSize bounds the dune-package and META files. They are small text files, which are not parsed like opam
// files: the largest dune-package files, which list every installed file, are a few hundred KB.
const maxLibraryFileSize = 16 * intFile.MB

var duneFieldPattern = regexp.MustCompile(`(?m)^\((name|version) ([^)\s]+)\)`)

// duneLangPattern matches the `(lang dune <version>)` line that starts every dune-package file.
var duneLangPattern = regexp.MustCompile(`(?m)^\(lang dune[ )]`)

// parseDunePackage parses the `dune-package` file that dune installs with every package (`<lib>/<name>/dune-package`).
// The dune package name is the opam package name. License and dependencies come from the sibling opam file.
func parseDunePackage(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	p := reader.Path()
	if isBuildOutput(p) || isInsideOpamSwitch(resolver, p) {
		return nil, nil, nil
	}
	data, err := readMetadataFileWithLimit(reader, maxLibraryFileSize)
	if err != nil {
		return nil, nil, err
	}
	if !duneLangPattern.Match(data) {
		// not a dune-package file, which says which dune language it uses
		return nil, nil, nil
	}
	var name, version string
	for _, m := range duneFieldPattern.FindAllSubmatch(data, -1) {
		switch string(m[1]) {
		case "name":
			name = string(m[2])
		case "version":
			version = knownVersion(string(m[2]))
		}
	}
	dir := path.Dir(p)
	if name == "" {
		name = path.Base(dir)
	}

	opam, opamLocation, hasOpam := readSiblingOpamFields(resolver, path.Join(dir, "opam"))
	if version == "" {
		version = opam.Version
	}
	if version == "" {
		if metaData, _, ok := readFile(resolver, path.Join(dir, "META"), maxLibraryFileSize); ok {
			if meta, isFindlib := parseFindlibFields(metaData); isFindlib && !meta.isCompilerShim() {
				version = meta.version
			}
		}
	}
	return []pkg.Package{installedLibraryPackage(ctx, opamMetadata(name, version, opam), reader.Location, opamLocation, hasOpam)}, nil, nil
}

// parseFindlibMeta parses a findlib `META` file for libraries installed without a dune-package file.
func parseFindlibMeta(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	p := reader.Path()
	dir := path.Dir(p)
	if isBuildOutput(p) || fileExists(resolver, path.Join(dir, "dune-package")) || isInsideOpamSwitch(resolver, p) {
		return nil, nil, nil
	}
	data, err := readMetadataFileWithLimit(reader, maxLibraryFileSize)
	if err != nil {
		return nil, nil, err
	}
	meta, isFindlib := parseFindlibFields(data)
	if !isFindlib || meta.isCompilerShim() {
		return nil, nil, nil
	}
	// a META file alone doesn't make an installed package: source trees carry META files (or templates of them,
	// e.g. topkg's pkg/META), and so does the compiler for the libraries it ships. Libraries installed by opam
	// have their opam file installed next to META. The directory is a findlib name, which only matches the
	// opam package name for such libraries.
	opam, opamLocation, hasOpam := readSiblingOpamFields(resolver, path.Join(dir, "opam"))
	if !hasOpam {
		return nil, nil, nil
	}
	name := path.Base(dir)
	if name == "/" || name == "." {
		return nil, nil, nil
	}
	version := meta.version
	if version == "" {
		version = opam.Version
	}
	return []pkg.Package{installedLibraryPackage(ctx, opamMetadata(name, version, opam), reader.Location, opamLocation, hasOpam)}, nil, nil
}

// installedLibraryPackage makes the package of an installed library. The opam file installed next to it, when present,
// is supporting evidence, and the source of its license.
func installedLibraryPackage(ctx context.Context, m pkg.OpamPackage, location, opamLocation file.Location, hasOpam bool) pkg.Package {
	p := newOpamPackage(ctx, m, location)
	if hasOpam {
		p.Locations.Add(opamLocation.WithoutAnnotations().WithAnnotation(pkg.EvidenceAnnotationKey, pkg.SupportingEvidenceAnnotation))
		p = withLicenseLocation(ctx, p, m.Licenses, opamLocation)
	}
	return p
}

type findlibFields struct {
	version   string
	directory string
}

// isCompilerShim reports whether the META file describes a library distributed with the OCaml compiler (such as
// findlib's META files for unix, str or bytes), which is not a separate package.
func (f findlibFields) isCompilerShim() bool {
	return strings.HasPrefix(f.version, "[") || f.directory == "^" || strings.HasPrefix(f.directory, "+")
}

var findlibAssignment = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*)(\([^)]*\))?\s*\+?=\s*"((?:[^"\\]|\\.)*)"`)

// parseFindlibFields reads the top-level `key = "value"` assignments of a META file (subpackages are ignored). The
// second return value reports whether the content looks like a findlib META file at all.
func parseFindlibFields(data []byte) (findlibFields, bool) {
	var out findlibFields
	isFindlib := false
	depth := 0
	// a subpackage may open its parenthesis on the line after `package "name"`
	openingNext := false
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if openingNext && line == "(" {
			openingNext = false
			depth++
			continue
		}
		openingNext = false
		if strings.HasPrefix(line, "package ") {
			if strings.HasSuffix(line, "(") {
				depth++
			} else {
				openingNext = true
			}
			continue
		}
		if line == ")" {
			depth--
			continue
		}
		m := findlibAssignment.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		isFindlib = true
		if depth > 0 {
			continue
		}
		switch m[1] {
		case "version":
			out.version = knownVersion(m[3])
		case "directory":
			out.directory = m[3]
		}
	}
	return out, isFindlib
}
