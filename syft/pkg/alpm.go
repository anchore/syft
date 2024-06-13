package pkg

import (
	"github.com/anchore/syft/syft/sort"
	stdSort "sort"
	"time"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

var _ FileOwner = (*AlpmDBEntry)(nil)

const AlpmDBGlob = "**/var/lib/pacman/local/**/desc"

// AlpmDBEntry is a struct that represents the package data stored in the pacman fla-filet stores for arch linux.
type AlpmDBEntry struct {
	BasePackage  string           `mapstructure:"base" json:"basepackage" cyclonedx:"basepackage"`
	Package      string           `mapstructure:"name" json:"package" cyclonedx:"package"`
	Version      string           `mapstructure:"version" json:"version" cyclonedx:"version"`
	Description  string           `mapstructure:"desc" json:"description" cyclonedx:"description"`
	Architecture string           `mapstructure:"arch" json:"architecture" cyclonedx:"architecture"`
	Size         int              `mapstructure:"size" json:"size" cyclonedx:"size"`
	Packager     string           `mapstructure:"packager" json:"packager"`
	URL          string           `mapstructure:"url" json:"url"`
	Validation   string           `mapstructure:"validation" json:"validation"`
	Reason       int              `mapstructure:"reason" json:"reason"`
	Files        []AlpmFileRecord `mapstructure:"files" json:"files"`
	Backup       []AlpmFileRecord `mapstructure:"backup" json:"backup"`
	Provides     []string         `mapstructure:"provides" json:"provides,omitempty"`
	Depends      []string         `mapstructure:"depends" json:"depends,omitempty"`
}

type AlpmFileRecord struct {
	Path    string        `mapstruture:"path" json:"path,omitempty"`
	Type    string        `mapstructure:"type" json:"type,omitempty"`
	UID     string        `mapstructure:"uid" json:"uid,omitempty"`
	GID     string        `mapstructure:"gid" json:"gid,omitempty"`
	Time    time.Time     `mapstructure:"time" json:"time,omitempty"`
	Size    string        `mapstructure:"size" json:"size,omitempty"`
	Link    string        `mapstructure:"link" json:"link,omitempty"`
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
	stdSort.Strings(result)
	return result
}

func (m AlpmFileRecord) Compare(other AlpmFileRecord) int {
	if i := sort.CompareOrd(m.Path, other.Path); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Type, other.Type); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.UID, other.UID); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.GID, other.GID); i != 0 {
		return i
	}
	if i := sort.Compare(m.Time, other.Time); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Size, other.Size); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Link, other.Link); i != 0 {
		return i
	}
	if i := sort.CompareArrays(m.Digests, other.Digests); i != 0 {
		return i
	}
	return 0
}
func (m AlpmDBEntry) Compare(other AlpmDBEntry) int {
	if i := sort.CompareOrd(m.BasePackage, other.BasePackage); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Package, other.Package); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Description, other.Description); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Architecture, other.Architecture); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Size, other.Size); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Packager, other.Packager); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.URL, other.URL); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Validation, other.Validation); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Reason, other.Reason); i != 0 {
		return i
	}
	if i := sort.CompareArrays(m.Files, other.Files); i != 0 {
		return i
	}
	if i := sort.CompareArrays(m.Backup, other.Backup); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.Provides, other.Provides); i != 0 {
		return i
	}
	if i := sort.CompareArraysOrd(m.Depends, other.Depends); i != 0 {
		return i
	}
	return 0
}
func (m AlpmDBEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(AlpmDBEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
