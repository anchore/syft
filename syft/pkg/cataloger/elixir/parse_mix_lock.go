package elixir

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// integrity check
var _ generic.Parser = parseMixLock

var mixLockDelimiter = regexp.MustCompile(`[%{}\n" ,:]+`)

// mixLockDependency matches each `{:name,` tuple opener on a mix.lock line. The
// first match is the entry's own source tuple (e.g. `{:hex, :name, ...}`); the
// remaining matches are the entry's dependency tuples within its dependency
// list (e.g. `[{:cowlib, ...}, {:ranch, ...}]`). Build-tool lists like
// `[:mix]` or `[:make, :rebar3]` and option keyword lists like
// `[hex: :cowlib, ...]` use bare atoms, not `{:atom,`, so they don't match.
var mixLockDependency = regexp.MustCompile(`\{\s*:(\w+)\s*,`)

// parseMixLock parses a mix.lock and returns the discovered Elixir packages.
func parseMixLock(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var errs error
	r := bufio.NewReader(reader)

	var packages []pkg.Package
	lineNum := 0
	for {
		lineNum++
		line, err := r.ReadString('\n')
		switch {
		case errors.Is(err, io.EOF):
			if errs == nil {
				errs = unknown.IfEmptyf(packages, "unable to determine packages")
			}
			return packages, nil, errs
		case err != nil:
			return nil, nil, fmt.Errorf("failed to parse mix.lock file: %w", err)
		}
		tokens := mixLockDelimiter.Split(line, -1)
		if len(tokens) < 6 {
			errs = unknown.Appendf(errs, reader, "unable to read mix lock line %d: %s", lineNum, line)
			continue
		}

		// tokens[2] is the source atom of the entry's tuple: `hex`, `git`, or
		// `path`. The layout of the remaining tokens differs per source, so the
		// version/hash positions must be read accordingly. Only hex entries are
		// backed by the hex.pm registry; git/path entries must not be emitted as
		// hex packages (see newPackage), otherwise a bogus pkg:hex/ PURL produces
		// false hex.pm vulnerability matches.
		source := tokens[2]

		var name, version, hash, hashExt string
		switch source {
		case "git":
			// e.g. `"dep": {:git, "https://host/dep.git", "<sha-or-ref>", [ref: "..."]}`
			// tokens: ["", name, "git", "<url-scheme>", "//host/dep.git", "<sha-or-ref>", ...]
			// The version is the commit SHA/ref immediately after the URL; there
			// is no hex checksum for a git-sourced dependency.
			name, version = tokens[1], tokens[5]
		case "path":
			// e.g. `"dep": {:path, "../local", []}`
			// tokens: ["", name, "path", "../local", "[]", ""]
			// A path dependency has no version or checksum; tokens[4] is the empty
			// dependency list `[]`, not a version.
			name = tokens[1]
		default:
			// hex (and any registry-style tuple): keep the original behavior.
			// tokens: ["", name, "hex", name, version, hash, ..., hashExt, ""]
			name, version, hash, hashExt = tokens[1], tokens[4], tokens[5], tokens[len(tokens)-2]
		}

		if name == "" {
			log.WithFields("path", reader.RealPath).Debug("skipping empty package name from mix.lock file")
			errs = unknown.Appendf(errs, reader, "skipping empty package name from mix.lock file, for line: %d: %s", lineNum, line)
			continue
		}

		packages = append(packages,
			newPackage(
				source,
				pkg.ElixirMixLockEntry{
					Name:         name,
					Version:      version,
					PkgHash:      hash,
					PkgHashExt:   hashExt,
					Dependencies: extractMixLockDependencies(line),
				},
				reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}
}

// extractMixLockDependencies returns the names of the packages depended on by
// the entry described on a single mix.lock line, by reading its dependency
// list. The entry's own source tuple (the first `{:atom,` on the line) is
// skipped; everything after it is a dependency.
func extractMixLockDependencies(line string) []string {
	matches := mixLockDependency.FindAllStringSubmatch(line, -1)
	if len(matches) <= 1 {
		return nil
	}
	deps := make([]string, 0, len(matches)-1)
	for _, m := range matches[1:] {
		deps = append(deps, m[1])
	}
	return deps
}
