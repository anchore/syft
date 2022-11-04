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
		WithParserByGlobs(parseRpmDB, pkg.RpmDBGlob).
		WithParserByGlobs(parseRpmManifest, pkg.RpmManifestGlob)
}

// NewFileCataloger returns a new RPM file cataloger object.
func NewFileCataloger() *generic.Cataloger {
	return generic.NewCataloger("rpm-file-cataloger").
		WithParserByGlobs(parseRpm, "**/*.rpm")
}
