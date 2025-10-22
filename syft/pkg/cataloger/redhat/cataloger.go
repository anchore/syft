/*
Package redhat provides a concrete DBCataloger implementation relating to packages within the RedHat linux distribution.
*/
package redhat

import (
	"database/sql"
	"fmt"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/dependency"
)

// NewDBCataloger returns a new RPM DB cataloger object.
func NewDBCataloger() pkg.Cataloger {
	return generic.NewCataloger("rpm-db-cataloger").
		WithParserByGlobs(parseRpmDB, pkg.RpmDBGlob).
		WithParserByGlobs(parseRpmManifest, pkg.RpmManifestGlob).
		WithProcessors(dependency.Processor(dbEntryDependencySpecifier), denySelfReferences).
		WithChecks(ensureSqliteDriverAvailable)
}

func denySelfReferences(pkgs []pkg.Package, rels []artifact.Relationship, err error) ([]pkg.Package, []artifact.Relationship, error) {
	// it can be common for dependency evidence to be self-referential (e.g. bash depends on bash), which is not useful
	// for the dependency graph, thus we remove these cases
	for i := 0; i < len(rels); i++ {
		if rels[i].Type != artifact.DependencyOfRelationship {
			continue
		}
		if rels[i].From.ID() == rels[i].To.ID() {
			rels = append(rels[:i], rels[i+1:]...)
			i--
		}
	}
	return pkgs, rels, err
}

// NewArchiveCataloger returns a new RPM file cataloger object.
func NewArchiveCataloger() pkg.Cataloger {
	return generic.NewCataloger("rpm-archive-cataloger").
		WithParserByGlobs(parseRpmArchive, "**/*.rpm")
}

func ensureSqliteDriverAvailable() error {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return fmt.Errorf("sqlite driver is required for cataloging newer RPM databases, none registered: %v", err)
	}
	_ = db.Close()
	return nil
}
