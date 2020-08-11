package rpmdb

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/cataloger/common"
	"github.com/anchore/syft/syft/pkg"
	rpmdb "github.com/wagoodman/go-rpmdb/pkg"
)

// integrity check
var _ common.ParserFn = parseRpmDB

func parseRpmDB(_ string, reader io.Reader) ([]pkg.Package, error) {
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
			Name:    entry.Name,
			Version: fmt.Sprintf("%s-%s", entry.Version, entry.Release), // this is what engine does
			//Version: fmt.Sprintf("%d:%s-%s.%s", entry.Epoch, entry.Version, entry.Release, entry.Arch),
			Type: pkg.RpmPkg,
			Metadata: pkg.RpmMetadata{
				Version:   entry.Version,
				Epoch:     entry.Epoch,
				Arch:      entry.Arch,
				Release:   entry.Release,
				SourceRpm: entry.SourceRpm,
				Vendor:    entry.Vendor,
				License:   entry.License,
				Size:      entry.Size,
			},
		}

		allPkgs = append(allPkgs, p)
	}

	return allPkgs, nil
}
