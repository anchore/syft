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
		name, version, hash, hashExt := tokens[1], tokens[4], tokens[5], tokens[len(tokens)-2]

		if name == "" {
			log.WithFields("path", reader.RealPath).Debug("skipping empty package name from mix.lock file")
			errs = unknown.Appendf(errs, reader, "skipping empty package name from mix.lock file, for line: %d: %s", lineNum, line)
			continue
		}

		packages = append(packages,
			newPackage(
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
