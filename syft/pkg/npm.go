package pkg

// NpmPackage represents the contents of a javascript package.json file.
type NpmPackage struct {
	// Name is the package name as found in package.json
	Name string `mapstructure:"name" json:"name"`

	// Version is the package version as found in package.json
	Version string `mapstructure:"version" json:"version"`

	// Author is package author name
	Author string `mapstructure:"author" json:"author"`

	// Homepage is project homepage URL
	Homepage string `mapstructure:"homepage" json:"homepage"`

	// Description is a human-readable package description
	Description string `mapstructure:"description" json:"description"`

	// URL is repository or project URL
	URL string `mapstructure:"url" json:"url"`

	// Private is whether this is a private package
	Private bool `mapstructure:"private" json:"private"`
}

// NpmPackageLockEntry represents a single entry within the "packages" section of a package-lock.json file.
type NpmPackageLockEntry struct {
	// Resolved is URL where this package was downloaded from (registry source)
	Resolved string `mapstructure:"resolved" json:"resolved"`

	// Integrity is Subresource Integrity hash for verification using standard SRI format (sha512-... or sha1-...). npm changed from SHA-1 to SHA-512 in newer versions. For registry sources this is the integrity from registry, for remote tarballs it's SHA-512 of the file. npm verifies tarball matches this hash before unpacking, throwing EINTEGRITY error if mismatch detected.
	Integrity string `mapstructure:"integrity" json:"integrity"`

	// Dependencies is a map of dependencies and their version markers, i.e. "lodash": "^1.0.0"
	Dependencies map[string]string `mapstructure:"dependencies" json:"dependencies"`
}

// YarnLockEntry represents a single entry section of a yarn.lock file.
type YarnLockEntry struct {
	// Resolved is URL where this package was downloaded from
	Resolved string `mapstructure:"resolved" json:"resolved"`

	// Integrity is Subresource Integrity hash for verification (SRI format)
	Integrity string `mapstructure:"integrity" json:"integrity"`

	// Dependencies is a map of dependencies and their versions
	Dependencies map[string]string `mapstructure:"dependencies" json:"dependencies"`
}

// PnpmLockResolution contains package resolution metadata from pnpm lockfiles, including the integrity hash used for verification.
type PnpmLockResolution struct {
	// Integrity is Subresource Integrity hash for verification (SRI format)
	Integrity string `mapstructure:"integrity" json:"integrity"`
}

// PnpmLockEntry represents a single entry in the "packages" section of a pnpm-lock.yaml file.
type PnpmLockEntry struct {
	// Resolution is the resolution information for the package
	Resolution PnpmLockResolution `mapstructure:"resolution" json:"resolution"`

	// Dependencies is a map of dependencies and their versions
	Dependencies map[string]string `mapstructure:"dependencies" json:"dependencies"`
}
