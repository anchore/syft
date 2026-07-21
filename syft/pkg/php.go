package pkg

// PhpComposerInstalledEntry represents a single package entry from a composer v1/v2 "installed.json" files (very similar to composer.lock files).
type PhpComposerInstalledEntry PhpComposerLockEntry

// PhpComposerLockEntry represents a single package entry found from a composer.lock file.
type PhpComposerLockEntry struct {
	// Name is package name in vendor/package format (e.g. symfony/console)
	Name string `json:"name"`

	// Version is the package version
	Version string `json:"version"`

	// Source is the source repository information for development (typically git repo, used when passing --prefer-source). Originates from source code repository.
	Source PhpComposerExternalReference `json:"source"`

	// Dist is distribution archive information for production (typically zip/tar, default install method). Packaged version of released code.
	Dist PhpComposerExternalReference `json:"dist"`

	// Require is runtime dependencies with version constraints (package will not install unless these requirements can be met)
	Require map[string]string `json:"require,omitempty"`

	// Provide is virtual packages/functionality provided by this package (allows other packages to depend on capabilities)
	Provide map[string]string `json:"provide,omitempty"`

	// RequireDev is development-only dependencies (not installed in production, only when developing this package or running tests)
	RequireDev map[string]string `json:"require-dev,omitempty"`

	// Suggest is optional but recommended dependencies (suggestions for packages that would extend functionality)
	Suggest map[string]string `json:"suggest,omitempty"`

	// License is the list of license identifiers (SPDX format)
	License []string `json:"license,omitempty"`

	// Type is package type indicating purpose (library=reusable code, project=application, metapackage=aggregates dependencies, etc.)
	Type string `json:"type,omitempty"`

	// NotificationURL is the URL to notify when package is installed (for tracking/statistics)
	NotificationURL string `json:"notification-url,omitempty"`

	// Bin is the list of binary/executable files that should be added to PATH
	Bin []string `json:"bin,omitempty"`

	// Authors are the list of package authors with name/email/homepage
	Authors []PhpComposerAuthors `json:"authors,omitempty"`

	// Description is a human-readable package description
	Description string `json:"description,omitempty"`

	// Homepage is project homepage URL
	Homepage string `json:"homepage,omitempty"`

	// Keywords are the list of keywords for package discovery/search
	Keywords []string `json:"keywords,omitempty"`

	// Time is timestamp when this package version was released
	Time string `json:"time,omitempty"`
}

// PhpComposerExternalReference represents source or distribution information for a PHP package, indicating where the package code is retrieved from.
type PhpComposerExternalReference struct {
	// Type is reference type (git for source VCS, zip/tar for dist archives)
	Type string `json:"type"`

	// URL is the URL to the resource (git repository URL or archive download URL)
	URL string `json:"url"`

	// Reference is git commit hash or version tag for source, or archive version for dist
	Reference string `json:"reference"`

	// Shasum is SHA hash of the archive file for integrity verification (dist only)
	Shasum string `json:"shasum,omitempty"`
}

// PhpComposerAuthors represents author information for a PHP Composer package from the authors field in composer.json.
type PhpComposerAuthors struct {
	// Name is author's full name
	Name string `json:"name"`

	// Email is author's email address
	Email string `json:"email,omitempty"`

	// Homepage is author's personal or company website
	Homepage string `json:"homepage,omitempty"`
}

// PhpPeclEntry represents a single package entry found within php pecl metadata files.
//
// Deprecated: please use PhpPearEntry instead with the pear cataloger.
type PhpPeclEntry PhpPearEntry

// PhpPearEntry represents a single package entry found within php pear metadata files.
type PhpPearEntry struct {
	// Name is the package name
	Name string `json:"name"`

	// Channel is PEAR channel this package is from
	Channel string `json:"channel,omitempty"`

	// Version is the package version
	Version string `json:"version"`

	// License is the list of applicable licenses
	License []string `json:"license,omitempty"`
}
