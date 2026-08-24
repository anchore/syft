package task

import (
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/ai"
	"github.com/anchore/syft/syft/pkg/cataloger/alpine"
	"github.com/anchore/syft/syft/pkg/cataloger/apple"
	"github.com/anchore/syft/syft/pkg/cataloger/arch"
	"github.com/anchore/syft/syft/pkg/cataloger/binary"
	bitnamiSbomCataloger "github.com/anchore/syft/syft/pkg/cataloger/bitnami"
	"github.com/anchore/syft/syft/pkg/cataloger/conda"
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
	"github.com/anchore/syft/syft/pkg/cataloger/homebrew"
	"github.com/anchore/syft/syft/pkg/cataloger/java"
	"github.com/anchore/syft/syft/pkg/cataloger/javascript"
	"github.com/anchore/syft/syft/pkg/cataloger/kernel"
	"github.com/anchore/syft/syft/pkg/cataloger/lua"
	"github.com/anchore/syft/syft/pkg/cataloger/nix"
	"github.com/anchore/syft/syft/pkg/cataloger/ocaml"
	"github.com/anchore/syft/syft/pkg/cataloger/php"
	"github.com/anchore/syft/syft/pkg/cataloger/python"
	"github.com/anchore/syft/syft/pkg/cataloger/r"
	"github.com/anchore/syft/syft/pkg/cataloger/redhat"
	"github.com/anchore/syft/syft/pkg/cataloger/ruby"
	"github.com/anchore/syft/syft/pkg/cataloger/rust"
	sbomCataloger "github.com/anchore/syft/syft/pkg/cataloger/sbom"
	"github.com/anchore/syft/syft/pkg/cataloger/snap"
	"github.com/anchore/syft/syft/pkg/cataloger/swift"
	"github.com/anchore/syft/syft/pkg/cataloger/swipl"
	"github.com/anchore/syft/syft/pkg/cataloger/terraform"
	"github.com/anchore/syft/syft/pkg/cataloger/wordpress"
)

const (
	// Java ecosystem labels
	Java  = "java"
	Maven = "maven"

	// Go ecosystem labels
	Go     = "go"
	Golang = "golang"

	// JavaScript ecosystem labels
	JavaScript = "javascript"
	Node       = "node"
	NPM        = "npm"

	// Python ecosystem labels
	Python = "python"

	// C/C++ ecosystem labels
	Cpp   = "cpp"
	Vcpkg = "vcpkg"
)

//nolint:funlen
func DefaultPackageTaskFactories() Factories {
	return Factories{
		// OS package installed catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory("alpm-db-cataloger", arch.NewDBCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "alpm", "archlinux", "pacman"),
		newSimplePackageTaskFactory("apk-db-cataloger", alpine.NewDBCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "apk", "alpine"),
		newSimplePackageTaskFactory("dpkg-db-cataloger", debian.NewDBCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "dpkg", "debian"),
		newSimplePackageTaskFactory("portage-cataloger", gentoo.NewPortageCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "portage", "gentoo"),
		newSimplePackageTaskFactory("rpm-db-cataloger", redhat.NewDBCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.OSTag, "linux", "rpm", "redhat"),

		// OS package declared catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory("rpm-archive-cataloger", redhat.NewArchiveCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.OSTag, "linux", "rpm", "redhat"),
		newSimplePackageTaskFactory("deb-archive-cataloger", debian.NewArchiveCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.OSTag, "linux", "deb", "debian"),

		// language-specific package installed catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory("conan-info-cataloger", cpp.NewConanInfoCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "cpp", "conan"),
		newSimplePackageTaskFactory("javascript-package-cataloger", javascript.NewPackageCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, JavaScript, Node),
		newSimplePackageTaskFactory("php-composer-installed-cataloger", php.NewComposerInstalledCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "php", "composer"),
		newSimplePackageTaskFactory("r-package-cataloger", r.NewPackageCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, pkgcataloging.DirectoryTag, "r"),
		newSimplePackageTaskFactory("ruby-installed-gemspec-cataloger", ruby.NewInstalledGemSpecCataloger, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "ruby", "gem", "gemspec"),
		newSimplePackageTaskFactory("cargo-auditable-binary-cataloger", rust.NewAuditBinaryCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "rust", "binary"),

		// language-specific package declared catalogers ///////////////////////////////////////////////////////////////////////////
		newSimplePackageTaskFactory("conan-cataloger", cpp.NewConanCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "cpp", "conan"),
		newPackageTaskFactory(
			"vcpkg-manifest-cataloger",
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return cpp.NewVcpkgManifestCataloger(cfg.PackagesConfig.Cpp)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, Cpp, Vcpkg),
		newSimplePackageTaskFactory("dart-pubspec-lock-cataloger", dart.NewPubspecLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "dart"),
		newSimplePackageTaskFactory("dart-pubspec-cataloger", dart.NewPubspecCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "dart"),
		newSimplePackageTaskFactory("elixir-mix-lock-cataloger", elixir.NewMixLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "elixir"),
		newSimplePackageTaskFactory("erlang-rebar-lock-cataloger", erlang.NewRebarLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "erlang"),
		newSimplePackageTaskFactory("erlang-otp-application-cataloger", erlang.NewOTPCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "erlang", "otp"),
		newSimplePackageTaskFactory("haskell-cataloger", haskell.NewHackageCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "haskell", "hackage", "cabal"),
		newPackageTaskFactory(
			"go-module-file-cataloger",
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return golang.NewGoModuleFileCataloger(cfg.PackagesConfig.Golang)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, Go, Golang, "gomod",
		),
		newSimplePackageTaskFactory("java-gradle-lockfile-cataloger", java.NewGradleLockfileCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, Java, "gradle"),
		newPackageTaskFactory(
			"java-pom-cataloger",
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return java.NewPomCataloger(cfg.PackagesConfig.JavaArchive)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, Java, Maven,
		),
		newPackageTaskFactory(
			"javascript-lock-cataloger",
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return javascript.NewLockCataloger(cfg.PackagesConfig.JavaScript)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, JavaScript, Node, NPM, "deno",
		),
		newSimplePackageTaskFactory("php-composer-lock-cataloger", php.NewComposerLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "php", "composer"),
		newSimplePackageTaskFactory("php-pear-serialized-cataloger", php.NewPearCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, pkgcataloging.ImageTag, "php", "pear"),
		newPackageTaskFactory(
			"python-package-cataloger",
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return python.NewPackageCataloger(cfg.PackagesConfig.Python)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, Python,
		),
		newSimplePackageTaskFactory("ruby-gemfile-cataloger", ruby.NewGemFileLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "ruby", "gem"),
		newSimplePackageTaskFactory("ruby-gemspec-cataloger", ruby.NewGemSpecCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "ruby", "gem", "gemspec"),
		newSimplePackageTaskFactory("rust-cargo-lock-cataloger", rust.NewCargoLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "rust", "cargo"),
		newSimplePackageTaskFactory("cocoapods-cataloger", swift.NewCocoapodsCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "swift", "cocoapods"),
		newSimplePackageTaskFactory("swift-package-manager-cataloger", swift.NewSwiftPackageManagerCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "swift", "spm"),
		newSimplePackageTaskFactory("swipl-pack-cataloger", swipl.NewSwiplPackCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "swipl", "pack"),
		newSimplePackageTaskFactory("opam-cataloger", ocaml.NewOpamPackageManagerCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "ocaml", "opam"),

		// language-specific package for both image and directory scans (but not necessarily declared) ////////////////////////////////////////
		newPackageTaskFactory(
			"dotnet-deps-binary-cataloger",
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return dotnet.NewDotnetDepsBinaryCataloger(cfg.PackagesConfig.Dotnet)
			},
			pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "dotnet", "c#",
		),
		newSimplePackageTaskFactory("dotnet-packages-lock-cataloger", dotnet.NewDotnetPackagesLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.ImageTag, pkgcataloging.DirectoryTag, pkgcataloging.LanguageTag, "dotnet", "c#"),
		newSimplePackageTaskFactory("python-installed-package-cataloger", python.NewInstalledPackageCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, Python),
		newPackageTaskFactory(
			"go-module-binary-cataloger",
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return golang.NewGoModuleBinaryCataloger(cfg.PackagesConfig.Golang)
			},
			pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, Go, Golang, "gomod", "binary",
		),
		newPackageTaskFactory(
			"java-archive-cataloger",
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return java.NewArchiveCataloger(cfg.PackagesConfig.JavaArchive)
			},
			pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, Java, Maven,
		),
		newSimplePackageTaskFactory("graalvm-native-image-cataloger", java.NewNativeImageCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, Java),
		newPackageTaskFactory(
			"nix-cataloger",
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return nix.NewCataloger(cfg.PackagesConfig.Nix)
			},
			pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "nix",
		),
		newSimplePackageTaskFactory("lua-rock-cataloger", lua.NewPackageCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, pkgcataloging.LanguageTag, "lua"),

		// other package catalogers ///////////////////////////////////////////////////////////////////////////
		newPackageTaskFactory(
			"binary-classifier-cataloger",
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return binary.NewClassifierCataloger(cfg.PackagesConfig.Binary)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "binary",
		),
		newSimplePackageTaskFactory("elf-binary-package-cataloger", binary.NewELFPackageCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "binary", "elf-package", "elf"),
		newSimplePackageTaskFactory("pe-binary-package-cataloger", binary.NewPEPackageCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "binary", "pe-package", "pe", "dll", "exe", "bpl"),
		newSimplePackageTaskFactory("github-actions-usage-cataloger", githubactions.NewActionUsageCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, "github", "github-actions"),
		newSimplePackageTaskFactory("github-action-workflow-usage-cataloger", githubactions.NewWorkflowUsageCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, "github", "github-actions"),
		newSimplePackageTaskFactory("java-jvm-cataloger", java.NewJvmDistributionCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "java", "jvm", "jdk", "jre"),
		newPackageTaskFactory(
			"linux-kernel-cataloger",
			func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return kernel.NewLinuxKernelCataloger(cfg.PackagesConfig.LinuxKernel)
			},
			pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "linux", "kernel",
		),
		newSimplePackageTaskFactory("php-interpreter-cataloger", php.NewInterpreterCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "binary", "php"),
		newSimplePackageTaskFactory("sbom-cataloger", sbomCataloger.NewCataloger, "sbom"), // note: not evidence of installed packages
		newSimplePackageTaskFactory("bitnami-cataloger", bitnamiSbomCataloger.NewCataloger, "bitnami", pkgcataloging.InstalledTag, pkgcataloging.ImageTag),
		newSimplePackageTaskFactory("wordpress-plugins-cataloger", wordpress.NewWordpressPluginCataloger, pkgcataloging.DirectoryTag, pkgcataloging.ImageTag, "wordpress"),
		newSimplePackageTaskFactory("terraform-lock-cataloger", terraform.NewLockCataloger, pkgcataloging.DeclaredTag, pkgcataloging.DirectoryTag, "terraform"),
		newSimplePackageTaskFactory("homebrew-cataloger", homebrew.NewCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "homebrew"),
		newSimplePackageTaskFactory("apple-app-bundle-cataloger", apple.NewAppBundleCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "apple"),
		newSimplePackageTaskFactory("conda-meta-cataloger", conda.NewCondaMetaCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.PackageTag, "conda"),
		newSimplePackageTaskFactory("snap-cataloger", snap.NewCataloger, pkgcataloging.DirectoryTag, pkgcataloging.InstalledTag, pkgcataloging.ImageTag, "snap"),
		newSimplePackageTaskFactory("gguf-cataloger", ai.NewGGUFCataloger, pkgcataloging.DirectoryTag, pkgcataloging.ImageTag, "ai", "model", "gguf", "ml"),

		// deprecated catalogers ////////////////////////////////////////
		// these are catalogers that should not be selectable other than specific inclusion via name or "deprecated" tag (to remain backwards compatible)
		newSimplePackageTaskFactory("dotnet-deps-cataloger", dotnet.NewDotnetDepsCataloger, pkgcataloging.DeprecatedTag),                              //nolint:staticcheck // TODO: remove in syft v2.0
		newSimplePackageTaskFactory("dotnet-portable-executable-cataloger", dotnet.NewDotnetPortableExecutableCataloger, pkgcataloging.DeprecatedTag), //nolint:staticcheck // TODO: remove in syft v2.0
		newSimplePackageTaskFactory("php-pecl-serialized-cataloger", php.NewPeclCataloger, pkgcataloging.DeprecatedTag),                               //nolint:staticcheck // TODO: remove in syft v2.0
		newSimplePackageTaskFactory("nix-store-cataloger", nix.NewStoreCataloger, pkgcataloging.DeprecatedTag),                                        //nolint:staticcheck // TODO: remove in syft v2.0
	}
}
