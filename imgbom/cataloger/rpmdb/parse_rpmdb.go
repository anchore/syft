package rpmdb

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/anchore/imgbom/internal"
	"github.com/anchore/imgbom/internal/log"
	rpmdb "github.com/wagoodman/go-rpmdb/pkg"
)

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
			Version: entry.Version,
			Type:    pkg.RpmPkg,
			Metadata: pkg.RpmMetadata{
				Epoch:   entry.Epoch,
				Arch:    entry.Arch,
				Release: entry.Release,
			},
		}

		allPkgs = append(allPkgs, p)
	}

	return allPkgs, nil
}
