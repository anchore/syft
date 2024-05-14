package redhat

import (
	"context"
	"fmt"
	"io"
	"os"

	rpmdb "github.com/knqyf263/go-rpmdb/pkg"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// parseRpmDb parses an "Packages" RPM DB and returns the Packages listed within it.
// nolint:funlen
func parseRpmDB(_ context.Context, resolver file.Resolver, env *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	f, err := os.CreateTemp("", "rpmdb")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create temp rpmdb file: %w", err)
	}

	defer func() {
		err = f.Close()
		if err != nil {
			log.Errorf("failed to close temp rpmdb file: %+v", err)
		}
		err = os.Remove(f.Name())
		if err != nil {
			log.Errorf("failed to remove temp rpmdb file: %+v", err)
		}
	}()

	_, err = io.Copy(f, reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to copy rpmdb contents to temp file: %w", err)
	}

	db, err := rpmdb.Open(f.Name())
	if err != nil {
		return nil, nil, err
	}
	defer db.Close()

	pkgList, err := db.ListPackages()
	if err != nil {
		return nil, nil, err
	}

	var allPkgs []pkg.Package

	var distro *linux.Release
	if env != nil {
		distro = env.LinuxRelease
	}

	for _, entry := range pkgList {
		if entry == nil {
			continue
		}

		metadata := pkg.RpmDBEntry{
			Name:            entry.Name,
			Version:         entry.Version,
			Epoch:           entry.Epoch,
			Arch:            entry.Arch,
			Release:         entry.Release,
			SourceRpm:       entry.SourceRpm,
			Vendor:          entry.Vendor,
			Size:            entry.Size,
			ModularityLabel: &entry.Modularitylabel,
			Files:           extractRpmFileRecords(resolver, *entry),
		}

		p := newDBPackage(
			reader.Location,
			metadata,
			distro,
			[]string{entry.License},
		)

		if !pkg.IsValid(&p) {
			log.WithFields("location", reader.RealPath, "pkg", fmt.Sprintf("%s@%s", entry.Name, entry.Version)).
				Warn("ignoring invalid package found in RPM DB")
			continue
		}

		p.SetID()
		allPkgs = append(allPkgs, p)
	}

	return allPkgs, nil, nil
}

// The RPM naming scheme is [name]-[version]-[release]-[arch], where version is implicitly expands to [epoch]:[version].
// RPM version comparison depends on comparing at least the version and release fields together as a subset of the
// naming scheme. This toELVersion function takes a RPM DB package information and converts it into a minimally comparable
// version string, containing epoch (optional), version, and release information. Epoch is an optional field and can be
// assumed to be 0 when not provided for comparison purposes, however, if the underlying RPM DB entry does not have
// an epoch specified it would be slightly disingenuous to display a value of 0.
func toELVersion(epoch *int, version, release string) string {
	if epoch != nil {
		return fmt.Sprintf("%d:%s-%s", *epoch, version, release)
	}
	return fmt.Sprintf("%s-%s", version, release)
}

func extractRpmFileRecords(resolver file.PathResolver, entry rpmdb.PackageInfo) []pkg.RpmFileRecord {
	var records = make([]pkg.RpmFileRecord, 0)

	files, err := entry.InstalledFiles()
	if err != nil {
		log.Warnf("unable to parse listing of installed files for RPM DB entry: %s", err.Error())
		return records
	}

	for _, record := range files {
		// only persist RPMDB file records which exist in the image/directory, otherwise ignore them
		if resolver.HasPath(record.Path) {
			records = append(records, pkg.RpmFileRecord{
				Path: record.Path,
				Mode: pkg.RpmFileMode(record.Mode),
				Size: int(record.Size),
				Digest: file.Digest{
					Value:     record.Digest,
					Algorithm: entry.DigestAlgorithm.String(),
				},
				UserName:  record.Username,
				GroupName: record.Groupname,
				Flags:     record.Flags.String(),
			})
		}
	}
	return records
}
