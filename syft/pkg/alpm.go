package pkg

import (
	"sort"
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
	sort.Strings(result)
	return result
}
