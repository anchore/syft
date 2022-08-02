package haskell

import (
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
	"gopkg.in/yaml.v3"
)

// integrity check
var _ common.ParserFn = parseStackLock

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

// parseStackLock is a parser function for stack.yaml.lock contents, returning all packages discovered.
func parseStackLock(_ string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load stack.yaml.lock file: %w", err)
	}

	var lockFile stackLock

	if err := yaml.Unmarshal(bytes, &lockFile); err != nil {
		return nil, nil, fmt.Errorf("failed to parse stack.yaml.lock file: %w", err)
	}

	var (
		pkgs        []*pkg.Package
		snapshotURL string
	)

	for _, snap := range lockFile.Snapshots {
		snapshotURL = snap.Completed.URL
	}

	for _, pack := range lockFile.Packages {
		pkgName, pkgVersion, pkgHash := parseStackPackageEncoding(pack.Completed.Hackage)
		pkgs = append(pkgs, &pkg.Package{
			Name:         pkgName,
			Version:      pkgVersion,
			Language:     pkg.Haskell,
			Type:         pkg.HackagePkg,
			MetadataType: pkg.HackageMetadataType,
			Metadata: pkg.HackageMetadata{
				Name:        pkgName,
				Version:     pkgVersion,
				PkgHash:     &pkgHash,
				SnapshotURL: &snapshotURL,
			},
		})
	}

	return pkgs, nil, nil
}
