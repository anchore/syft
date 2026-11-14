package ocaml

import (
	"bufio"
	"bytes"
	"context"
	"path"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var duneFieldPattern = regexp.MustCompile(`(?m)^\((name|version) ([^)\s]+)\)`)

// parseDunePackage parses the `dune-package` file that dune installs with every package (`<lib>/<name>/dune-package`).
// The dune package name is the opam package name. License and dependencies come from the sibling opam file.
func parseDunePackage(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	p := reader.Path()
	if isBuildOutput(p) || isInsideOpamSwitch(resolver, p) {
		return nil, nil, nil
	}
	data, err := readMetadataFile(reader)
	if err != nil {
		return nil, nil, err
	}
	var name, version string
	for _, m := range duneFieldPattern.FindAllSubmatch(data, -1) {
		switch string(m[1]) {
		case "name":
			name = string(m[2])
		case "version":
			version = string(m[2])
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
		if metaData, _, ok := readFile(resolver, path.Join(dir, "META")); ok {
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
	data, err := readMetadataFile(reader)
	if err != nil {
		return nil, nil, err
	}
	meta, isFindlib := parseFindlibFields(data)
	if !isFindlib || meta.isCompilerShim() {
		return nil, nil, nil
	}
	name := path.Base(dir)
	opam, opamLocation, hasOpam := readSiblingOpamFields(resolver, path.Join(dir, "opam"))
	version := meta.version
	if version == "" {
		version = opam.Version
	}
	return []pkg.Package{installedLibraryPackage(ctx, opamMetadata(name, version, opam), reader.Location, opamLocation, hasOpam)}, nil, nil
}

func installedLibraryPackage(ctx context.Context, m pkg.OpamPackage, location, opamLocation file.Location, hasOpam bool) pkg.Package {
	p := newOpamPackage(ctx, m, location)
	if hasOpam {
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
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "package ") && strings.HasSuffix(line, "(") {
			depth++
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
			out.version = m[3]
		case "directory":
			out.directory = m[3]
		}
	}
	return out, isFindlib
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
