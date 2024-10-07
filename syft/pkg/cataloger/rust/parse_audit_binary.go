package rust

import (
	"context"
	"errors"
	"fmt"

	rustaudit "github.com/microsoft/go-rustaudit"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// Catalog identifies executables then attempts to read Rust dependency information from them
func parseAuditBinary(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	unionReader, err := unionreader.GetUnionReader(reader.ReadCloser)
	if err != nil {
		return nil, nil, err
	}

	infos, err := parseAuditBinaryEntry(unionReader, reader.RealPath)
	for _, versionInfo := range infos {
		pkgs = append(pkgs, newPackagesFromAudit(reader.Location, versionInfo)...)
	}

	return pkgs, nil, err
}

// scanFile scans file to try to report the Rust crate dependencies
func parseAuditBinaryEntry(reader unionreader.UnionReader, filename string) ([]rustaudit.VersionInfo, error) {
	// NOTE: multiple readers are returned to cover universal binaries, which are files
	// with more than one binary
	readers, err := unionreader.GetReaders(reader)
	if err != nil {
		log.Warnf("rust cataloger: failed to open a binary: %v", err)
		return nil, fmt.Errorf("rust cataloger: failed to open a binary: %w", err)
	}

	var versionInfos []rustaudit.VersionInfo
	for _, r := range readers {
		versionInfo, err := rustaudit.GetDependencyInfo(r)

		if err != nil {
			if errors.Is(err, rustaudit.ErrNoRustDepInfo) {
				// since the cataloger can only select executables and not distinguish if they are a Rust-compiled
				// binary, we should not show warnings/logs in this case.
				return nil, nil
			}
			log.Tracef("rust cataloger: unable to read dependency information (file=%q): %v", filename, err)
			return nil, fmt.Errorf("rust cataloger: unable to read dependency information: %w", err)
		}

		versionInfos = append(versionInfos, versionInfo)
	}

	return versionInfos, nil
}
