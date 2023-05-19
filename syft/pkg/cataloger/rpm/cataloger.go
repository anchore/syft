/*
Package rpm provides a concrete DBCataloger implementation for RPM "Package" DB files and a FileCataloger for RPM files.
*/
package rpm

import (
	"database/sql"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewRpmDBCataloger returns a new RPM DB cataloger object.
func NewRpmDBCataloger() *generic.Cataloger {
	// check if a sqlite driver is available
	if !isSqliteDriverAvailable() {
		log.Warnf("sqlite driver is not available, newer RPM databases might not be cataloged")
	}

	return generic.NewCataloger("rpm-db-cataloger").
		WithParserByGlobs(parseRpmDB, pkg.RpmDBGlob).
		WithParserByGlobs(parseRpmManifest, pkg.RpmManifestGlob)
}

// NewFileCataloger returns a new RPM file cataloger object.
func NewFileCataloger() *generic.Cataloger {
	return generic.NewCataloger("rpm-file-cataloger").
		WithParserByGlobs(parseRpm, "**/*.rpm")
}

func isSqliteDriverAvailable() bool {
	_, err := sql.Open("sqlite", ":memory:")
	return err == nil
}
