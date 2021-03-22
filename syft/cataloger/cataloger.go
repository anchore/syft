/*
Package cataloger provides the ability to process files from a container image or file system and discover packages
(gems, wheels, jars, rpms, debs, etc). Specifically, this package contains both a catalog function to utilize all
catalogers defined in child packages as well as the interface definition to implement a cataloger.
*/
package cataloger

import (
	"github.com/anchore/syft/syft/cataloger/apkdb"
	"github.com/anchore/syft/syft/cataloger/deb"
	"github.com/anchore/syft/syft/cataloger/golang"
	"github.com/anchore/syft/syft/cataloger/java"
	"github.com/anchore/syft/syft/cataloger/javascript"
	"github.com/anchore/syft/syft/cataloger/python"
	"github.com/anchore/syft/syft/cataloger/rpmdb"
	"github.com/anchore/syft/syft/cataloger/ruby"
	"github.com/anchore/syft/syft/cataloger/rust"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// Cataloger describes behavior for an object to participate in parsing container image or file system
// contents for the purpose of discovering Packages. Each concrete implementation should focus on discovering Packages
// for a specific Package Type or ecosystem.
type Cataloger interface {
	// Name returns a string that uniquely describes a cataloger
	Name() string
	// Catalog is given an object to resolve file references and content, this function returns any discovered Packages after analyzing the catalog source.
	Catalog(resolver source.Resolver) ([]pkg.Package, error)
}

// ImageCatalogers returns a slice of locally implemented catalogers that are fit for detecting installations of packages.
func ImageCatalogers() []Cataloger {
	return []Cataloger{
		ruby.NewGemSpecCataloger(),
		python.NewPythonPackageCataloger(),
		javascript.NewJavascriptPackageCataloger(),
		deb.NewDpkgdbCataloger(),
		rpmdb.NewRpmdbCataloger(),
		java.NewJavaCataloger(),
		apkdb.NewApkdbCataloger(),
		golang.NewGoModCataloger(),
		rust.NewCargoLockCataloger(),
	}
}

// DirectoryCatalogers returns a slice of locally implemented catalogers that are fit for detecting packages from index files (and select installations)
func DirectoryCatalogers() []Cataloger {
	return []Cataloger{
		ruby.NewGemFileLockCataloger(),
		python.NewPythonIndexCataloger(),
		python.NewPythonPackageCataloger(),
		javascript.NewJavascriptLockCataloger(),
		deb.NewDpkgdbCataloger(),
		rpmdb.NewRpmdbCataloger(),
		java.NewJavaCataloger(),
		apkdb.NewApkdbCataloger(),
		golang.NewGoModCataloger(),
		rust.NewCargoLockCataloger(),
	}
}
