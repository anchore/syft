package packages

import (
	"github.com/anchore/syft/syft/cataloger/packages/apkdb"
	"github.com/anchore/syft/syft/cataloger/packages/deb"
	"github.com/anchore/syft/syft/cataloger/packages/golang"
	"github.com/anchore/syft/syft/cataloger/packages/java"
	"github.com/anchore/syft/syft/cataloger/packages/javascript"
	"github.com/anchore/syft/syft/cataloger/packages/php"
	"github.com/anchore/syft/syft/cataloger/packages/python"
	"github.com/anchore/syft/syft/cataloger/packages/rpmdb"
	"github.com/anchore/syft/syft/cataloger/packages/ruby"
	"github.com/anchore/syft/syft/cataloger/packages/rust"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

// TODO: add tag-based API to select appropriate package catalogers for different scenarios

// AllCatalogers returns all implemented package catalogers
func AllCatalogers(cfg SearchConfig) []pkg.Cataloger {
	return []pkg.Cataloger{
		ruby.NewGemFileLockCataloger(),
		ruby.NewGemSpecCataloger(),
		python.NewPythonIndexCataloger(),
		python.NewPythonPackageCataloger(),
		javascript.NewJavascriptLockCataloger(),
		javascript.NewJavascriptPackageCataloger(),
		deb.NewDpkgdbCataloger(),
		rpmdb.NewRpmdbCataloger(),
		java.NewJavaCataloger(cfg.Java()),
		apkdb.NewApkdbCataloger(),
		golang.NewGoModuleBinaryCataloger(),
		golang.NewGoModFileCataloger(),
		rust.NewCargoLockCataloger(),
	}
}

// InstalledCatalogers returns a slice of locally implemented package catalogers that are fit for detecting installations of packages.
func InstalledCatalogers(cfg SearchConfig) []pkg.Cataloger {
	return []pkg.Cataloger{
		ruby.NewGemSpecCataloger(),
		python.NewPythonPackageCataloger(),
		php.NewPHPComposerInstalledCataloger(),
		javascript.NewJavascriptPackageCataloger(),
		deb.NewDpkgdbCataloger(),
		rpmdb.NewRpmdbCataloger(),
		java.NewJavaCataloger(cfg.Java()),
		apkdb.NewApkdbCataloger(),
		golang.NewGoModuleBinaryCataloger(),
	}
}

// IndexCatalogers returns a slice of locally implemented package catalogers that are fit for detecting packages from index files (and select installations)
func IndexCatalogers(cfg SearchConfig) []pkg.Cataloger {
	return []pkg.Cataloger{
		ruby.NewGemFileLockCataloger(),
		python.NewPythonIndexCataloger(),
		python.NewPythonPackageCataloger(), // for install
		php.NewPHPComposerLockCataloger(),
		javascript.NewJavascriptLockCataloger(),
		deb.NewDpkgdbCataloger(),            // for install
		rpmdb.NewRpmdbCataloger(),           // for install
		java.NewJavaCataloger(cfg.Java()),   // for install
		apkdb.NewApkdbCataloger(),           // for install
		golang.NewGoModuleBinaryCataloger(), // for install
		golang.NewGoModFileCataloger(),
		rust.NewCargoLockCataloger(),
	}
}

func CatalogersBySourceScheme(scheme source.Type, cfg SearchConfig) []pkg.Cataloger {
	switch scheme {
	case source.ImageType:
		return InstalledCatalogers(cfg)
	case source.FileType:
		return AllCatalogers(cfg)
	case source.DirectoryType:
		return IndexCatalogers(cfg)
	}
	return nil
}
