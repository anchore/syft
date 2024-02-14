package task

import (
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
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
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	"github.com/anchore/syft/syft/pkg/cataloger/nix"
	"github.com/anchore/syft/syft/pkg/cataloger/php"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/pkg/cataloger/r"
	"github.com/anchore/syft/syft/pkg/cataloger/redhat"
	"github.com/anchore/syft/syft/pkg/cataloger/ruby"
	"github.com/anchore/syft/syft/pkg/cataloger/rust"
	sbomCataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/anchore/syft/syft/pkg/cataloger/swift"
	"github.com/anchore/syft/syft/pkg/cataloger/wordpress"
)

//nolint:funlen
func DefaultPackageTaskFactories() PackageTaskFactories {
	return []packageTaskFactory{
		// OS package installed catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory(arch.NewDBCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "alpm", "archlinux"),
		newSimplePackageTaskFactory(alpine.NewDBCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "apk", "alpine"),
		newSimplePackageTaskFactory(debian.NewDBCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "dpkg", "debian"),
		newSimplePackageTaskFactory(gentoo.NewPortageCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "portage", "gentoo"),
		newSimplePackageTaskFactory(redhat.NewDBCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "rpm", "redhat"),

		// OS package declared catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory(redhat.NewArchiveCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.OSTag, "linux", "rpm", "redhat"),

		// language-specific package installed catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory(cpp.NewConanInfoCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "cpp", "conan"),
		newSimplePackageTaskFactory(javascript.NewPackageCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "javascript", "node"),
		newSimplePackageTaskFactory(php.NewComposerInstalledCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "php", "composer"),
		newSimplePackageTaskFactory(r.NewPackageCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "r"),
		newSimplePackageTaskFactory(ruby.NewInstalledGemSpecCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "ruby", "gem", "gemspec"),
		newSimplePackageTaskFactory(rust.NewAuditBinaryCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "rust", "binary"),

		// language-specific package declared catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory(cpp.NewConanCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "cpp", "conan"),
		newSimplePackageTaskFactory(dart.NewPubspecLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "dart"),
		newSimplePackageTaskFactory(dotnet.NewDotnetDepsCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "dotnet", "c#"),
		newSimplePackageTaskFactory(elixir.NewMixLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "elixir"),
		newSimplePackageTaskFactory(erlang.NewRebarLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "erlang"),
		newSimplePackageTaskFactory(erlang.NewOTPCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "erlang", "otp"),
		newSimplePackageTaskFactory(haskell.NewHackageCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "haskell", "hackage", "cabal"),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return golang.NewGoModuleFileCataloger(cfg.PackagesConfig.Golang)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "go", "golang", "gomod",
		),
		newSimplePackageTaskFactory(java.NewGradleLockfileCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "java", "gradle"),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return java.NewPomCataloger(cfg.PackagesConfig.JavaArchive)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "java", "maven",
		),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return javascript.NewLockCataloger(cfg.PackagesConfig.JavaScript)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "javascript", "node", "npm",
		),
		newSimplePackageTaskFactory(php.NewComposerLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "php", "composer"),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return python.NewPackageCataloger(cfg.PackagesConfig.Python)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "python",
		),
		newSimplePackageTaskFactory(ruby.NewGemFileLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "ruby", "gem"),
		newSimplePackageTaskFactory(ruby.NewGemSpecCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "ruby", "gem", "gemspec"),
		newSimplePackageTaskFactory(rust.NewCargoLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "rust", "cargo"),
		newSimplePackageTaskFactory(swift.NewCocoapodsCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "swift", "cocoapods"),
		newSimplePackageTaskFactory(swift.NewSwiftPackageManagerCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "swift", "spm"),

		// language-specific package for both image and directory scans (but not necessarily declared) ////////////////////////////////////////
		newSimplePackageTaskFactory(dotnet.NewDotnetPortableExecutableCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "dotnet", "c#", "binary"),
		newSimplePackageTaskFactory(python.NewInstalledPackageCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "python"),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return golang.NewGoModuleBinaryCataloger(cfg.PackagesConfig.Golang)
			},
			pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "go", "golang", "gomod", "binary",
		),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return java.NewArchiveCataloger(cfg.PackagesConfig.JavaArchive)
			},
			pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "java", "maven",
		),
		newSimplePackageTaskFactory(java.NewNativeImageCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "java"),
		newSimplePackageTaskFactory(nix.NewStoreCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "nix"),

		// other package catalogers ///////////////////////////////////////////////////////////////////////////
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return binary.NewClassifierCataloger(cfg.PackagesConfig.Binary)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "binary",
		),
		newSimplePackageTaskFactory(githubactions.NewActionUsageCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, "github", "github-actions"),
		newSimplePackageTaskFactory(githubactions.NewWorkflowUsageCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, "github", "github-actions"),
		newPackageTaskFactory(
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return kernel.NewLinuxKernelCataloger(cfg.PackagesConfig.LinuxKernel)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "linux", "kernel",
		),
		newSimplePackageTaskFactory(sbomCataloger.NewCataloger, "sbom"), // note: not evidence of installed packages
		newSimplePackageTaskFactory(wordpress.NewWordpressPluginCataloger, pkgcataloging.DirectoryTag, pkgcataloging.ImageTag, "wordpress"),
	}
}
