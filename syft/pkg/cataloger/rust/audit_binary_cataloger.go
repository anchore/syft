package rust

import (
	"fmt"

	rustaudit "github.com/microsoft/go-rustaudit"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/unionreader"
	"github.com/anchore/syft/syft/source"
)

const catalogerName = "cargo-auditable-binary-cataloger"

type Cataloger struct{}

// NewRustAuditBinaryCataloger returns a new Rust auditable binary cataloger object that can detect dependencies
// in binaries produced with https://github.com/Shnatsel/rust-audit
func NewRustAuditBinaryCataloger() *Cataloger {
	return &Cataloger{}
}

// Name returns a string that uniquely describes a cataloger
func (c *Cataloger) Name() string {
	return catalogerName
}

// UsesExternalSources indicates that the audit binary cataloger does not use external sources
func (c *Cataloger) UsesExternalSources() bool {
	return false
}

// Catalog identifies executables then attempts to read Rust dependency information from them
func (c *Cataloger) Catalog(resolver source.FileResolver) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package

	fileMatches, err := resolver.FilesByMIMEType(internal.ExecutableMIMETypeSet.List()...)
	if err != nil {
		return pkgs, nil, fmt.Errorf("failed to find bin by mime types: %w", err)
	}

	for _, location := range fileMatches {
		readerCloser, err := resolver.FileContentsByLocation(location)
		if err != nil {
			log.Warnf("rust cataloger: opening file: %v", err)
			continue
		}

		reader, err := unionreader.GetUnionReader(readerCloser)
		if err != nil {
			return nil, nil, err
		}

		versionInfos := scanFile(reader, location.RealPath)
		internal.CloseAndLogError(readerCloser, location.RealPath)

		for _, versionInfo := range versionInfos {
			pkgs = append(pkgs, buildRustPkgInfo(location, versionInfo)...)
		}
	}

	return pkgs, nil, nil
}

// scanFile scans file to try to report the Rust crate dependencies
func scanFile(reader unionreader.UnionReader, filename string) []rustaudit.VersionInfo {
	// NOTE: multiple readers are returned to cover universal binaries, which are files
	// with more than one binary
	readers, err := unionreader.GetReaders(reader)
	if err != nil {
		log.Warnf("rust cataloger: failed to open a binary: %v", err)
		return nil
	}

	var versionInfos []rustaudit.VersionInfo
	for _, r := range readers {
		versionInfo, err := rustaudit.GetDependencyInfo(r)

		if err != nil {
			if err == rustaudit.ErrNoRustDepInfo {
				// since the cataloger can only select executables and not distinguish if they are a Rust-compiled
				// binary, we should not show warnings/logs in this case.
				return nil
			}
			// Use an Info level log here like golang/scan_bin.go
			log.Infof("rust cataloger: unable to read dependency information (file=%q): %v", filename, err)
			return nil
		}

		versionInfos = append(versionInfos, versionInfo)
	}

	return versionInfos
}

func buildRustPkgInfo(location source.Location, versionInfo rustaudit.VersionInfo) []pkg.Package {
	var pkgs []pkg.Package

	for _, dep := range versionInfo.Packages {
		dep := dep
		p := newRustPackage(&dep, location)
		if pkg.IsValid(&p) && dep.Kind == rustaudit.Runtime {
			pkgs = append(pkgs, p)
		}
	}

	return pkgs
}

func newRustPackage(dep *rustaudit.Package, location source.Location) pkg.Package {
	p := pkg.Package{
		FoundBy:      catalogerName,
		Name:         dep.Name,
		Version:      dep.Version,
		Language:     pkg.Rust,
		Type:         pkg.RustPkg,
		Locations:    source.NewLocationSet(location),
		MetadataType: pkg.RustCargoPackageMetadataType,
		Metadata: pkg.CargoPackageMetadata{
			Name:    dep.Name,
			Version: dep.Version,
			Source:  dep.Source,
		},
	}

	p.SetID()

	return p
}
