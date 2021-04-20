package rpmdb

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/anchore/syft/syft/file"

	rpmdb "github.com/anchore/go-rpmdb/pkg"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// parseApkDb parses an "Packages" RPM DB and returns the Packages listed within it.
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

	allPkgs := make([]pkg.Package, 0)

	for _, entry := range pkgList {
		p := pkg.Package{
			Name:         entry.Name,
			Version:      fmt.Sprintf("%s-%s", entry.Version, entry.Release), // this is what engine does, instead of fmt.Sprintf("%d:%s-%s.%s", entry.Epoch, entry.Version, entry.Release, entry.Arch)
			Locations:    []source.Location{dbLocation},
			FoundBy:      catalogerName,
			Type:         pkg.RpmPkg,
			MetadataType: pkg.RpmdbMetadataType,
			Metadata: pkg.RpmdbMetadata{
				Name:      entry.Name,
				Version:   entry.Version,
				Epoch:     entry.Epoch,
				Arch:      entry.Arch,
				Release:   entry.Release,
				SourceRpm: entry.SourceRpm,
				Vendor:    entry.Vendor,
				License:   entry.License,
				Size:      entry.Size,
				Files:     extractRpmdbFileRecords(resolver, entry),
			},
		}

		allPkgs = append(allPkgs, p)
	}

	return allPkgs, nil
}

func extractRpmdbFileRecords(resolver source.FilePathResolver, entry *rpmdb.PackageInfo) []pkg.RpmdbFileRecord {
	var records = make([]pkg.RpmdbFileRecord, 0)

	for _, record := range entry.Files {
		//only persist RPMDB file records which exist in the image/directory, otherwise ignore them
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
	return records
}
