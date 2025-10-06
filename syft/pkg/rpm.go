package pkg

import (
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

// RpmDBGlob is the glob pattern used to find RPM DB files. Where:
// - /var/lib/rpm/... is the typical path for most distributions
// - /usr/share/rpm/... is common for rpm-ostree distributions (coreos-like)
// - Packages is the legacy Berkeley db based format
// - Packages.db is the "ndb" format used in SUSE
// - rpmdb.sqlite is the sqlite format used in fedora + derivates
const RpmDBGlob = "**/{var/lib,usr/share,usr/lib/sysimage}/rpm/{Packages,Packages.db,rpmdb.sqlite}"

// RpmManifestGlob is used in CBL-Mariner distroless images
const RpmManifestGlob = "**/var/lib/rpmmanifest/container-manifest-2"

var _ FileOwner = (*RpmDBEntry)(nil)

// RpmArchive represents package metadata extracted directly from a .rpm archive file, containing the same information as an RPM database entry.
type RpmArchive RpmDBEntry

// RpmDBEntry represents all captured data from a RPM DB package entry.
type RpmDBEntry struct {
	// Name is the RPM package name as found in the RPM database.
	Name string `json:"name"`

	// Version is the upstream version of the package.
	Version string `json:"version"`

	// Epoch is the version epoch used to force upgrade ordering (null if not set).
	Epoch *int `json:"epoch"  cyclonedx:"epoch" jsonschema:"nullable"`

	// Arch is the target CPU architecture (e.g., "x86_64", "aarch64", "noarch").
	Arch string `json:"architecture"`

	// Release is the package release number or distribution-specific version suffix.
	Release string `json:"release" cyclonedx:"release"`

	// SourceRpm is the source RPM filename that was used to build this package.
	SourceRpm string `json:"sourceRpm" cyclonedx:"sourceRpm"`

	// Signatures contains GPG signature metadata for package verification.
	Signatures []RpmSignature `json:"signatures,omitempty" cyclonedx:"signatures"`

	// Size is the total installed size of the package in bytes.
	Size int `json:"size" cyclonedx:"size"`

	// Vendor is the organization that packaged the software.
	Vendor string `json:"vendor"`

	// ModularityLabel identifies the module stream for modular RPM packages (e.g., "nodejs:12:20200101").
	ModularityLabel *string `json:"modularityLabel,omitempty" cyclonedx:"modularityLabel"`

	// Provides lists the virtual packages and capabilities this package provides.
	Provides []string `json:"provides,omitempty"`

	// Requires lists the dependencies required by this package.
	Requires []string `json:"requires,omitempty"`

	// Files are the file records for all files owned by this package.
	Files []RpmFileRecord `json:"files"`
}

// RpmSignature represents a GPG signature for an RPM package used for authenticity verification.
type RpmSignature struct {
	// PublicKeyAlgorithm is the public key algorithm used for signing (e.g., "RSA").
	PublicKeyAlgorithm string `json:"algo"`

	// HashAlgorithm is the hash algorithm used for the signature (e.g., "SHA256").
	HashAlgorithm string `json:"hash"`

	// Created is the timestamp when the signature was created.
	Created string `json:"created"`

	// IssuerKeyID is the GPG key ID that created the signature.
	IssuerKeyID string `json:"issuer"`
}

func (s RpmSignature) String() string {
	if s.PublicKeyAlgorithm == "" && s.HashAlgorithm == "" && s.Created == "" && s.IssuerKeyID == "" {
		return ""
	}
	// mimics the output you would see from rpm -q --qf "%{RSAHEADER}"
	// e.g."RSA/SHA256, Mon May 16 12:32:55 2022, Key ID 702d426d350d275d"
	return strings.Join([]string{s.PublicKeyAlgorithm + "/" + s.HashAlgorithm, s.Created, "Key ID " + s.IssuerKeyID}, ", ")
}

// RpmFileRecord represents the file metadata for a single file attributed to a RPM package.
type RpmFileRecord struct {
	// Path is the absolute file path where the file is installed.
	Path string `json:"path"`

	// Mode is the file permission mode bits following Unix stat.h conventions.
	Mode RpmFileMode `json:"mode"`

	// Size is the file size in bytes.
	Size int `json:"size"`

	// Digest contains the hash algorithm and value for file integrity verification.
	Digest file.Digest `json:"digest"`

	// UserName is the owner username for the file.
	UserName string `json:"userName"`

	// GroupName is the group name for the file.
	GroupName string `json:"groupName"`

	// Flags indicates the file type (e.g., "%config", "%doc", "%ghost").
	Flags string `json:"flags"`
}

// RpmFileMode is the raw file mode for a single file. This can be interpreted as the linux stat.h mode (see https://pubs.opengroup.org/onlinepubs/007908799/xsh/sysstat.h.html)
type RpmFileMode uint16

func (m RpmDBEntry) OwnedFiles() (result []string) {
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
