package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

var _ FileOwner = (*PythonPackageMetadata)(nil)

// PythonFileDigest represents the file metadata for a single file attributed to a python package.
type PythonFileDigest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

// PythonFileRecord represents a single entry within a RECORD file for a python wheel or egg package
type PythonFileRecord struct {
	Path   string            `json:"path"`
	Digest *PythonFileDigest `json:"digest,omitempty"`
	Size   string            `json:"size,omitempty"`
}

// PythonPackageMetadata represents all captured data for a python egg or wheel package.
type PythonPackageMetadata struct {
	Name                 string             `json:"name" mapstruct:"Name"`
	Version              string             `json:"version" mapstruct:"Version"`
	License              string             `json:"license" mapstruct:"License"`
	Author               string             `json:"author" mapstruct:"Author"`
	AuthorEmail          string             `json:"authorEmail" mapstruct:"Authoremail"`
	Platform             string             `json:"platform" mapstruct:"Platform"`
	Files                []PythonFileRecord `json:"files,omitempty"`
	SitePackagesRootPath string             `json:"sitePackagesRootPath"`
	TopLevelPackages     []string           `json:"topLevelPackages,omitempty"`
	DirectURL            DirectURL          `json:"directUrl,omitempty"`
}

type DirectURL struct {
	URL     string `json:"url"`
	VCSInfo `json:"vcsInfo"`
}

type VCSInfo struct {
	CommitID string `json:"commitId"`
	VCS      string `json:"vcs"`
}

func (m PythonPackageMetadata) OwnedFiles() (result []string) {
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
