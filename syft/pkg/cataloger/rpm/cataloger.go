/*
Package rpm provides a concrete DBCataloger implementation for RPM "Package" DB files and a FileCataloger for RPM files.
*/
package rpm

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

// NewRpmDBCataloger returns a new RPM DB cataloger object.
func NewRpmDBCataloger() *generic.Cataloger {
	return generic.NewCataloger("rpm-db-cataloger").
		WithParser(parseRpmDB,
			generic.NewSearch().ByBasename("Packages").MustMatchGlob(pkg.RpmDBGlob),
			generic.NewSearch().ByBasename("Packages.db").MustMatchGlob(pkg.RpmDBGlob),
			generic.NewSearch().ByBasename("rpmdb.sqlite").MustMatchGlob(pkg.RpmDBGlob),
		).
		WithParser(parseRpmManifest,
			generic.NewSearch().ByBasename("container-manifest-2").MustMatchGlob(pkg.RpmManifestGlob),
		)
}

// NewFileCataloger returns a new RPM file cataloger object.
func NewFileCataloger() *generic.Cataloger {
	return generic.NewCataloger("rpm-file-cataloger").
		WithParserByExtensions(parseRpm, ".rpm")
}
