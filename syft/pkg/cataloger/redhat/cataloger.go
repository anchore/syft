/*
Package redhat provides a concrete DBCataloger implementation relating to packages within the RedHat linux distribution.
*/
package redhat

import (
	"database/sql"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewDBCataloger returns a new RPM DB cataloger object.
func NewDBCataloger() *generic.Cataloger {
	// check if a sqlite driver is available
	if !isSqliteDriverAvailable() {
		log.Warnf("sqlite driver is not available, newer RPM databases might not be cataloged")
	}

	return generic.NewCataloger("rpm-db-cataloger").
		WithParserByGlobs(parseRpmDB, pkg.RpmDBGlob).
		WithParserByGlobs(parseRpmManifest, pkg.RpmManifestGlob)
}

// NewArchiveCataloger returns a new RPM file cataloger object.
func NewArchiveCataloger() *generic.Cataloger {
	return generic.NewCataloger("rpm-archive-cataloger").
		WithParserByGlobs(parseRpmArchive, "**/*.rpm")
}

func isSqliteDriverAvailable() bool {
	_, err := sql.Open("sqlite", ":memory:")
	return err == nil
}
