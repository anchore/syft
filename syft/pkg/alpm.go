package pkg

import (
	"sort"
	"time"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

var _ FileOwner = (*AlpmDBEntry)(nil)

const AlpmDBGlob = "**/var/lib/pacman/local/**/desc"

// AlpmDBEntry is a struct that represents the package data stored in the pacman flat-file stores for arch linux.
type AlpmDBEntry struct {
	// BasePackage is the base package name this package was built from (source package in Arch build system)
	BasePackage string `mapstructure:"base" json:"basepackage" cyclonedx:"basepackage"`

	// Package is the package name as found in the desc file
	Package string `mapstructure:"name" json:"package" cyclonedx:"package"`

	// Version is the package version as found in the desc file
	Version string `mapstructure:"version" json:"version" cyclonedx:"version"`

	// Description is a human-readable package description
	Description string `mapstructure:"desc" json:"description" cyclonedx:"description"`

	// Architecture is the target CPU architecture as defined in Arch architecture spec (e.g. x86_64, aarch64, or "any" for arch-independent packages)
	Architecture string `mapstructure:"arch" json:"architecture" cyclonedx:"architecture"`

	// Size is the installed size in bytes
	Size int `mapstructure:"size" json:"size" cyclonedx:"size"`

	// Packager is the name and email of the person who packaged this (RFC822 format)
	Packager string `mapstructure:"packager" json:"packager"`

	// URL is the upstream project URL
	URL string `mapstructure:"url" json:"url"`

	// Validation is the validation method used for package integrity (e.g. pgp signature, sha256 checksum)
	Validation string `mapstructure:"validation" json:"validation"`

	// Reason is the installation reason tracked by pacman (0=explicitly installed by user, 1=installed as dependency)
	Reason int `mapstructure:"reason" json:"reason"`

	// Files are the files installed by this package
	Files []AlpmFileRecord `mapstructure:"files" json:"files"`

	// Backup is the list of configuration files that pacman backs up before upgrades
	Backup []AlpmFileRecord `mapstructure:"backup" json:"backup"`

	// Provides are virtual packages provided by this package (allows other packages to depend on capabilities rather than specific packages)
	Provides []string `mapstructure:"provides" json:"provides,omitempty"`

	// Depends are the runtime dependencies required by this package
	Depends []string `mapstructure:"depends" json:"depends,omitempty"`
}

type AlpmFileRecord struct {
	// Path is the file path relative to the filesystem root
	Path string `mapstruture:"path" json:"path,omitempty"`

	// Type is the file type (e.g. regular file, directory, symlink)
	Type string `mapstructure:"type" json:"type,omitempty"`

	// UID is the file owner user ID as recorded by pacman
	UID string `mapstructure:"uid" json:"uid,omitempty"`

	// GID is the file owner group ID as recorded by pacman
	GID string `mapstructure:"gid" json:"gid,omitempty"`

	// Time is the file modification timestamp
	Time time.Time `mapstructure:"time" json:"time,omitempty"`

	// Size is the file size in bytes
	Size string `mapstructure:"size" json:"size,omitempty"`

	// Link is the symlink target path if this is a symlink
	Link string `mapstructure:"link" json:"link,omitempty"`

	// Digests contains file content hashes for integrity verification
	Digests []file.Digest `mapstructure:"digests" json:"digest,omitempty"`
}

func (m AlpmDBEntry) OwnedFiles() (result []string) {
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
