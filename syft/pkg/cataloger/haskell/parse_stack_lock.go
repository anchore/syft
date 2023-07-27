package haskell

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseStackLock

type stackLock struct {
	Packages  []stackPackage  `yaml:"packages"`
	Snapshots []stackSnapshot `yaml:"snapshots"`
}

type stackPackage struct {
	Completed completedPackage `yaml:"completed"`
}

type completedPackage struct {
	Hackage string `yaml:"hackage"`
}

type stackSnapshot struct {
	Completed completedSnapshot `yaml:"completed"`
}

type completedSnapshot struct {
	URL string `yaml:"url"`
	Sha string `yaml:"sha256"`
}

// parseStackLock is a parser function for stack.yaml.lock contents, returning all packages discovered.
func parseStackLock(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load stack.yaml.lock file: %w", err)
	}

	var lockFile stackLock

	if err := yaml.Unmarshal(bytes, &lockFile); err != nil {
		return nil, nil, fmt.Errorf("failed to parse stack.yaml.lock file: %w", err)
	}

	var (
		pkgs        []pkg.Package
		snapshotURL string
	)

	for _, snap := range lockFile.Snapshots {
		// TODO: handle multiple snapshots (split the metadata struct into more distinct structs and types)
		snapshotURL = snap.Completed.URL
	}

	for _, pack := range lockFile.Packages {
		pkgName, pkgVersion, pkgHash := parseStackPackageEncoding(pack.Completed.Hackage)
		pkgs = append(
			pkgs,
			newPackage(
				pkgName,
				pkgVersion,
				&pkg.HackageMetadata{
					PkgHash:     pkgHash,
					SnapshotURL: snapshotURL,
				},
				reader.Location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
			),
		)
	}

	return pkgs, nil, nil
}
func parseStackPackageEncoding(pkgEncoding string) (name, version, hash string) {
	lastDashIdx := strings.LastIndex(pkgEncoding, "-")
	name = pkgEncoding[:lastDashIdx]
	remainingEncoding := pkgEncoding[lastDashIdx+1:]
	encodingSplits := strings.Split(remainingEncoding, "@")
	version = encodingSplits[0]
	startHash, endHash := strings.Index(encodingSplits[1], ":")+1, strings.Index(encodingSplits[1], ",")
	hash = encodingSplits[1][startHash:endHash]
	return
}
