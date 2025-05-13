package pkgcataloging

const (
	// InstalledTag is to identify packages found to be positively installed.
	InstalledTag = "installed"

	// DeclaredTag is to identify packages described but not necessarily installed.
	DeclaredTag = "declared"

	// ImageTag indicates the cataloger should be used when cataloging images.
	ImageTag = "image"

	// DirectoryTag indicates the cataloger should be used when cataloging directories.
	DirectoryTag = "directory"

	// PackageTag should be used to identify catalogers that are package-based.
	PackageTag = "package"

	// OSTag should be used to identify catalogers that cataloging OS packages.
	OSTag = "os"

	// LanguageTag should be used to identify catalogers that cataloging language-specific packages.
	LanguageTag = "language"

	// DeprecatedTag should be used to identify catalogers that are deprecated.
	DeprecatedTag = "deprecated"
)
