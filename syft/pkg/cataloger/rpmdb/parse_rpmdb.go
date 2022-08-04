package rpmdb

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
	rpmdb "github.com/knqyf263/go-rpmdb/pkg"
)

// parseRpmDb parses an "Packages" RPM DB and returns the Packages listed within it.
func parseRpmDB(resolver source.FilePathResolver, dbLocation source.Location, reader io.Reader) ([]pkg.Package, error) {
	f, err := ioutil.TempFile("", internal.ApplicationName+"-rpmdb")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp rpmdb file: %w", err)
	}

	defer func() {
		err = os.Remove(f.Name())
		if err != nil {
			log.Errorf("failed to remove temp rpmdb file: %+v", err)
		}
	}()

	_, err = io.Copy(f, reader)
	if err != nil {
		return nil, fmt.Errorf("failed to copy rpmdb contents to temp file: %w", err)
	}

	db, err := rpmdb.Open(f.Name())
	if err != nil {
		return nil, err
	}

	pkgList, err := db.ListPackages()
	if err != nil {
		return nil, err
	}

	var allPkgs []pkg.Package

	for _, entry := range pkgList {
		p, err := newPkg(resolver, dbLocation, entry)
		if err != nil {
			return nil, err
		}

		if !pkg.IsValid(p) {
			continue
		}

		p.SetID()
		allPkgs = append(allPkgs, *p)
	}

	return allPkgs, nil
}

func newPkg(resolver source.FilePathResolver, dbLocation source.Location, entry *rpmdb.PackageInfo) (*pkg.Package, error) {
	fileRecords, err := extractRpmdbFileRecords(resolver, entry)
	if err != nil {
		return nil, err
	}

	metadata := pkg.RpmdbMetadata{
		Name:      entry.Name,
		Version:   entry.Version,
		Epoch:     entry.Epoch,
		Arch:      entry.Arch,
		Release:   entry.Release,
		SourceRpm: entry.SourceRpm,
		Vendor:    entry.Vendor,
		License:   entry.License,
		Size:      entry.Size,
		ModularityLabel:  entry.Modularitylabel,
		Files:     fileRecords,
	}

	p := pkg.Package{
		Name:         entry.Name,
		Version:      toELVersion(metadata),
		Locations:    source.NewLocationSet(dbLocation),
		FoundBy:      catalogerName,
		Type:         pkg.RpmPkg,
		MetadataType: pkg.RpmdbMetadataType,
		Metadata:     metadata,
	}

	p.SetID()
	return &p, nil
}

// The RPM naming scheme is [name]-[version]-[release]-[arch], where version is implicitly expands to [epoch]:[version].
// RPM version comparison depends on comparing at least the version and release fields together as a subset of the
// naming scheme. This toELVersion function takes a RPM DB package information and converts it into a minimally comparable
// version string, containing epoch (optional), version, and release information. Epoch is an optional field and can be
// assumed to be 0 when not provided for comparison purposes, however, if the underlying RPM DB entry does not have
// an epoch specified it would be slightly disingenuous to display a value of 0.
func toELVersion(metadata pkg.RpmdbMetadata) string {
	if metadata.Epoch != nil {
		return fmt.Sprintf("%d:%s-%s", *metadata.Epoch, metadata.Version, metadata.Release)
	}
	return fmt.Sprintf("%s-%s", metadata.Version, metadata.Release)
}

func extractRpmdbFileRecords(resolver source.FilePathResolver, entry *rpmdb.PackageInfo) ([]pkg.RpmdbFileRecord, error) {
	var records = make([]pkg.RpmdbFileRecord, 0)

	files, err := entry.InstalledFiles()
	if err != nil {
		return nil, err
	}

	for _, record := range files {
		// only persist RPMDB file records which exist in the image/directory, otherwise ignore them
		if resolver.HasPath(record.Path) {
			records = append(records, pkg.RpmdbFileRecord{
				Path: record.Path,
				Mode: pkg.RpmdbFileMode(record.Mode),
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
	return records, nil
}
