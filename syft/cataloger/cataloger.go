/*
Package cataloger provides the ability to process files from a container image or file system and discover packages
(gems, wheels, jars, rpms, debs, etc). Specifically, this package contains both a catalog function to utilize all
catalogers defined in child packages as well as the interface definition to implement a cataloger.
*/
package cataloger

import (
	"io"

	"github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/syft/cataloger/apkdb"
	"github.com/anchore/syft/syft/cataloger/bundler"
	"github.com/anchore/syft/syft/cataloger/golang"
	"github.com/anchore/syft/syft/cataloger/java"
	"github.com/anchore/syft/syft/cataloger/javascript"
	"github.com/anchore/syft/syft/cataloger/python"
	"github.com/anchore/syft/syft/cataloger/rpmdb"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/scope"
)

// Cataloger describes behavior for an object to participate in parsing container image or file system
// contents for the purpose of discovering Packages. Each concrete implementation should focus on discovering Packages
// for a specific Package Type or ecosystem.
type Cataloger interface {
	// Name returns a string that uniquely describes a cataloger
	Name() string
	// SelectFiles discovers and returns specific files that the cataloger would like to inspect the contents of.
	SelectFiles(scope.FileResolver) []file.Reference
	// Catalog is given the file contents and should return any discovered Packages after analyzing the contents.
	Catalog(map[file.Reference]io.Reader) ([]pkg.Package, error)
	// TODO: add "IterationNeeded" error to indicate to the driver to continue with another Select/Catalog pass
}

// All returns a slice of all locally defined catalogers (defined in child packages).
func BuiltIn() []Cataloger {
	return []Cataloger{
		//dpkg.New(),
		bundler.New(),
		python.New(),
		rpmdb.New(),
		java.New(),
		apkdb.New(),
		golang.New(),
		javascript.New(),
	}
}
