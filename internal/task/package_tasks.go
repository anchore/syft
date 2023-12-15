package task

import (
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/alpine"
	"github.com/anchore/syft/syft/pkg/cataloger/arch"
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
	"github.com/anchore/syft/syft/pkg/cataloger/cpp"
	"github.com/anchore/syft/syft/pkg/cataloger/dart"
	"github.com/anchore/syft/syft/pkg/cataloger/debian"
	"github.com/anchore/syft/syft/pkg/cataloger/dotnet"
	"github.com/anchore/syft/syft/pkg/cataloger/elixir"
	"github.com/anchore/syft/syft/pkg/cataloger/erlang"
	"github.com/anchore/syft/syft/pkg/cataloger/gentoo"
	"github.com/anchore/syft/syft/pkg/cataloger/githubactions"
	"github.com/anchore/syft/syft/pkg/cataloger/golang"
	"github.com/anchore/syft/syft/pkg/cataloger/haskell"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/nix"
	"github.com/anchore/syft/syft/pkg/cataloger/php"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/pkg/cataloger/r"
	"github.com/anchore/syft/syft/pkg/cataloger/redhat"
	"github.com/anchore/syft/syft/pkg/cataloger/ruby"
	"github.com/anchore/syft/syft/pkg/cataloger/rust"
	sbomCataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/anchore/syft/syft/pkg/cataloger/swift"
)

//nolint:funlen
func DefaultPackageTaskFactories() PackageTaskFactories {
	return []packageTaskFactory{
		// OS package installed catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory(arch.NewDBCataloger, DirectoryTag, InstalledTag, ImageTag, OSTag, "linux", "alpm", "archlinux"),
		newSimplePackageTaskFactory(alpine.NewDBCataloger, DirectoryTag, InstalledTag, ImageTag, OSTag, "linux", "apk", "alpine"),
		newSimplePackageTaskFactory(debian.NewDBCataloger, DirectoryTag, InstalledTag, ImageTag, OSTag, "linux", "dpkg", "debian"),
		newSimplePackageTaskFactory(gentoo.NewPortageCataloger, DirectoryTag, InstalledTag, ImageTag, OSTag, "linux", "portage", "gentoo"),
		newSimplePackageTaskFactory(redhat.NewDBCataloger, DirectoryTag, InstalledTag, ImageTag, OSTag, "linux", "rpm", "redhat"),

		// OS package declared catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory(redhat.NewArchiveCataloger, DeclaredTag, DirectoryTag, OSTag, "linux", "rpm", "redhat"),

		// language-specific package installed catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory(cpp.NewConanInfoCataloger, InstalledTag, ImageTag, LanguageTag, "cpp", "conan"),
		newSimplePackageTaskFactory(javascript.NewPackageCataloger, InstalledTag, ImageTag, LanguageTag, "javascript", "node"),
		newSimplePackageTaskFactory(php.NewComposerInstalledCataloger, InstalledTag, ImageTag, LanguageTag, "php", "composer"),
		newSimplePackageTaskFactory(r.NewPackageCataloger, InstalledTag, ImageTag, LanguageTag, "r"),
		newSimplePackageTaskFactory(ruby.NewInstalledGemSpecCataloger, InstalledTag, ImageTag, LanguageTag, "ruby", "gem", "gemspec"),
		newSimplePackageTaskFactory(rust.NewAuditBinaryCataloger, InstalledTag, ImageTag, LanguageTag, "rust", "binary"),

		// language-specific package declared catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory(cpp.NewConanCataloger, DeclaredTag, DirectoryTag, LanguageTag, "cpp", "conan"),
		newSimplePackageTaskFactory(dart.NewPubspecLockCataloger, DeclaredTag, DirectoryTag, LanguageTag, "dart"),
		newSimplePackageTaskFactory(dotnet.NewDotnetDepsCataloger, DeclaredTag, DirectoryTag, LanguageTag, "dotnet", "c#"),
		newSimplePackageTaskFactory(elixir.NewMixLockCataloger, DeclaredTag, DirectoryTag, LanguageTag, "elixir"),
		newSimplePackageTaskFactory(erlang.NewRebarLockCataloger, DeclaredTag, DirectoryTag, LanguageTag, "erlang"),
		newSimplePackageTaskFactory(haskell.NewHackageCataloger, DeclaredTag, DirectoryTag, LanguageTag, "haskell", "hackage", "cabal"),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return golang.NewGoModuleFileCataloger(cfg.PackagesConfig.Golang)
			},
			DeclaredTag, DirectoryTag, LanguageTag, "go", "golang", "gomod",
		),
		newSimplePackageTaskFactory(java.NewGradleLockfileCataloger, DeclaredTag, DirectoryTag, LanguageTag, "java", "gradle"),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return java.NewPomCataloger(cfg.PackagesConfig.JavaArchive)
			},
			DeclaredTag, DirectoryTag, LanguageTag, "java", "maven",
		),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return javascript.NewLockCataloger(cfg.PackagesConfig.Javascript)
			},
			DeclaredTag, DirectoryTag, LanguageTag, "javascript", "node", "npm",
		),
		newSimplePackageTaskFactory(php.NewComposerLockCataloger, DeclaredTag, DirectoryTag, LanguageTag, "php", "composer"),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return python.NewPackageCataloger(cfg.PackagesConfig.Python)
			},
			DeclaredTag, DirectoryTag, LanguageTag, "python",
		),
		newSimplePackageTaskFactory(ruby.NewGemFileLockCataloger, DeclaredTag, DirectoryTag, LanguageTag, "ruby", "gem"),
		newSimplePackageTaskFactory(ruby.NewGemSpecCataloger, DeclaredTag, DirectoryTag, LanguageTag, "ruby", "gem", "gemspec"),
		newSimplePackageTaskFactory(rust.NewCargoLockCataloger, DeclaredTag, DirectoryTag, LanguageTag, "rust", "cargo"),
		newSimplePackageTaskFactory(swift.NewCocoapodsCataloger, DeclaredTag, DirectoryTag, LanguageTag, "swift", "cocoapods"),
		newSimplePackageTaskFactory(swift.NewSwiftPackageManagerCataloger, DeclaredTag, DirectoryTag, LanguageTag, "swift", "spm"),

		// language-specific package for both image and directory scans (but not necessarily declared) ////////////////////////////////////////
		newSimplePackageTaskFactory(dotnet.NewDotnetPortableExecutableCataloger, DirectoryTag, InstalledTag, ImageTag, LanguageTag, "dotnet", "c#", "binary"),
		newSimplePackageTaskFactory(python.NewInstalledPackageCataloger, DirectoryTag, InstalledTag, ImageTag, LanguageTag, "python"),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return golang.NewGoModuleBinaryCataloger(cfg.PackagesConfig.Golang)
			},
			DirectoryTag, InstalledTag, ImageTag, LanguageTag, "go", "golang", "gomod", "binary",
		),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return java.NewArchiveCataloger(cfg.PackagesConfig.JavaArchive)
			},
			DirectoryTag, InstalledTag, ImageTag, LanguageTag, "java", "maven",
		),
		newSimplePackageTaskFactory(java.NewNativeImageCataloger, DirectoryTag, InstalledTag, ImageTag, LanguageTag, "java"),
		newSimplePackageTaskFactory(nix.NewStoreCataloger, DirectoryTag, InstalledTag, ImageTag, LanguageTag, "nix"),

		// other package catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory(binary.NewCataloger, DeclaredTag, DirectoryTag, InstalledTag, ImageTag, "binary"),
		newSimplePackageTaskFactory(githubactions.NewActionUsageCataloger, DeclaredTag, DirectoryTag, "github", "github-actions"),
		newSimplePackageTaskFactory(githubactions.NewWorkflowUsageCataloger, DeclaredTag, DirectoryTag, "github", "github-actions"),
		newSimplePackageTaskFactory(sbomCataloger.NewCataloger, ImageTag, DeclaredTag, DirectoryTag, ImageTag, "sbom"), // note: not evidence of installed packages
	}
}
