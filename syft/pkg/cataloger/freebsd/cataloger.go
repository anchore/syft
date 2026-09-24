/*
Package freebsd provides a concrete Cataloger implementation relating to packages within the FreeBSD distribution,
as tracked by the pkgng package manager's local database (local.sqlite).
*/
package freebsd

import (
	"database/sql"
	"fmt"

	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewDBCataloger returns a new FreeBSD pkgng DB cataloger object.
func NewDBCataloger() pkg.Cataloger {
	return generic.NewCataloger("freebsd-db-cataloger").
		WithParserByGlobs(parsePkgDB, pkg.FreeBSDPkgDBGlob).
		WithChecks(ensureSqliteDriverAvailable)
}

// NewArchiveCataloger returns a new FreeBSD pkgng cataloger capable of parsing pkgng package archive (.pkg)
// files.
func NewArchiveCataloger() pkg.Cataloger {
	return generic.NewCataloger("freebsd-pkg-cataloger").
		WithParserByGlobs(parsePkgArchive, "**/*.pkg")
}

func ensureSqliteDriverAvailable() error {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return fmt.Errorf("sqlite driver is required for cataloging FreeBSD pkgng databases, none registered: %v", err)
	}
	_ = db.Close()
	return nil
}
