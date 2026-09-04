package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

// FreeBSDPkgDBGlob is the glob pattern used to find the FreeBSD pkgng local package database.
const FreeBSDPkgDBGlob = "**/var/db/pkg/local.sqlite"

var _ FileOwner = (*FreeBSDPkgDBEntry)(nil)

// FreeBSDPkgDBEntry represents all captured data from a FreeBSD pkgng "packages" table row, along with the
// files attributed to the package from the "files" table.
type FreeBSDPkgDBEntry struct {
	// Origin is the port origin the package was built from (e.g. "www/curl").
	Origin string `json:"origin"`

	// Name is the package name as found in the pkgng database.
	Name string `json:"name"`

	// Version is the package version, potentially including a port revision and epoch (e.g. "1.2.3_1,1").
	Version string `json:"version"`

	// Comment is a one-line summary of the package.
	Comment string `json:"comment,omitempty"`

	// Description is the long-form package description.
	Description string `json:"description,omitempty"`

	// Arch is the target architecture and ABI (e.g. "FreeBSD:14:amd64").
	Arch string `json:"architecture"`

	// Maintainer is the email address of the person or team maintaining the port.
	Maintainer string `json:"maintainer,omitempty"`

	// WWW is the upstream project website.
	WWW string `json:"www,omitempty"`

	// Prefix is the installation prefix for the package (e.g. "/usr/local").
	Prefix string `json:"prefix,omitempty"`

	// FlatSize is the total installed size of the package in bytes.
	FlatSize int64 `json:"flatSize"`

	// Automatic indicates the package was installed as a dependency rather than explicitly requested.
	Automatic bool `json:"automatic"`

	// Locked indicates the package is locked from being automatically upgraded or removed.
	Locked bool `json:"locked"`

	// LicenseLogic indicates how multiple licenses combine ("single", "or", "and").
	LicenseLogic string `json:"licenseLogic,omitempty"`

	// Licenses are the license names attributed to the package, as recorded in the "licenses" table and
	// joined via the "pkg_licenses" table.
	Licenses []string `json:"licenses,omitempty"`

	// ManifestDigest is the digest of the package manifest used for integrity verification.
	ManifestDigest string `json:"manifestDigest,omitempty"`

	// Vital indicates the package is protected from accidental removal.
	Vital bool `json:"vital"`

	// Files are the file records for all files owned by this package.
	Files []FreeBSDFileRecord `json:"files"`
}

// FreeBSDFileRecord represents the file metadata for a single file attributed to a FreeBSD package,
// as recorded in the pkgng "files" table.
type FreeBSDFileRecord struct {
	// Path is the absolute file path where the file is installed.
	Path string `json:"path"`

	// Digest is the sha256 digest of the file contents as recorded at install time.
	Digest string `json:"digest,omitempty"`

	// UserName is the owner username for the file.
	UserName string `json:"userName,omitempty"`

	// GroupName is the group name for the file.
	GroupName string `json:"groupName,omitempty"`
}

func (m FreeBSDPkgDBEntry) OwnedFiles() (result []string) {
	s := strset.New()
	for _, f := range m.Files {
		if f.Path != "" {
			s.Add(f.Path)
		}
	}
	result = s.List()
	sort.Strings(result)
	return result
}

var _ FileOwner = (*FreeBSDPkgArchiveEntry)(nil)

// FreeBSDPkgArchiveEntry represents package metadata extracted from a FreeBSD pkgng package archive (.pkg)
// file's "+MANIFEST" entry.
type FreeBSDPkgArchiveEntry struct {
	// Origin is the port origin the package was built from (e.g. "www/curl").
	Origin string `json:"origin"`

	// Name is the package name as found in the manifest.
	Name string `json:"name"`

	// Version is the package version, potentially including a port revision and epoch (e.g. "1.2.3_1,1").
	Version string `json:"version"`

	// Comment is a one-line summary of the package.
	Comment string `json:"comment,omitempty"`

	// Description is the long-form package description.
	Description string `json:"description,omitempty"`

	// WWW is the upstream project website.
	WWW string `json:"www,omitempty"`

	// Maintainer is the email address of the person or team maintaining the port.
	Maintainer string `json:"maintainer,omitempty"`

	// ABI is the target platform, OS release, and architecture the package was built for
	// (e.g. "FreeBSD:14:amd64").
	ABI string `json:"abi,omitempty"`

	// Arch is the target architecture the package was built for, in ports arch format
	// (e.g. "freebsd:14:x86:64").
	Arch string `json:"architecture,omitempty"`

	// Prefix is the installation prefix for the package (e.g. "/usr/local").
	Prefix string `json:"prefix,omitempty"`

	// FlatSize is the total installed size of the package in bytes.
	FlatSize int64 `json:"flatSize"`

	// LicenseLogic indicates how multiple licenses combine ("single", "or", "and").
	LicenseLogic string `json:"licenseLogic,omitempty"`

	// Licenses are the license names attributed to the package.
	Licenses []string `json:"licenses,omitempty"`

	// Categories are the port categories the package is classified under (e.g. "www").
	Categories []string `json:"categories,omitempty"`

	// ShlibsRequired are the shared libraries required by the package's binaries.
	ShlibsRequired []string `json:"shlibsRequired,omitempty"`

	// Annotations are free-form key/value metadata attached to the package by the ports build.
	Annotations map[string]string `json:"annotations,omitempty"`

	// Files are the file records for all files owned by this package, as recorded in the manifest.
	Files []FreeBSDFileRecord `json:"files"`
}

func (m FreeBSDPkgArchiveEntry) OwnedFiles() (result []string) {
	s := strset.New()
	for _, f := range m.Files {
		if f.Path != "" {
			s.Add(f.Path)
		}
	}
	result = s.List()
	sort.Strings(result)
	return result
}
