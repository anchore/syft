package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

var _ FileOwner = (*PythonPackage)(nil)

// PythonPackage represents all captured data for a python egg or wheel package (specifically as outlined in
// the PyPA core metadata specification https://packaging.python.org/en/latest/specifications/core-metadata/).
// Historically these were defined in PEPs 345, 314, and 241, but have been superseded by PEP 566. This means that this
// struct can (partially) express at least versions 1.0, 1.1, 1.2, 2.1, 2.2, and 2.3 of the metadata format.
type PythonPackage struct {
	Name                 string                     `json:"name" mapstruct:"Name"`
	Version              string                     `json:"version" mapstruct:"Version"`
	Author               string                     `json:"author" mapstruct:"Author"`
	AuthorEmail          string                     `json:"authorEmail" mapstruct:"Authoremail"`
	Platform             string                     `json:"platform" mapstruct:"Platform"`
	Files                []PythonFileRecord         `json:"files,omitempty"`
	SitePackagesRootPath string                     `json:"sitePackagesRootPath"`
	TopLevelPackages     []string                   `json:"topLevelPackages,omitempty"`
	DirectURLOrigin      *PythonDirectURLOriginInfo `json:"directUrlOrigin,omitempty"`
	RequiresPython       string                     `json:"requiresPython,omitempty" mapstruct:"RequiresPython"`
	RequiresDist         []string                   `json:"requiresDist,omitempty" mapstruct:"RequiresDist"`
	ProvidesExtra        []string                   `json:"providesExtra,omitempty" mapstruct:"ProvidesExtra"`
}

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

type PythonDirectURLOriginInfo struct {
	URL      string `json:"url"`
	CommitID string `json:"commitId,omitempty"`
	VCS      string `json:"vcs,omitempty"`
}

func (m PythonPackage) OwnedFiles() (result []string) {
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

// PythonPipfileLockEntry represents a single package entry within a Pipfile.lock file.
type PythonPipfileLockEntry struct {
	Hashes []string `mapstructure:"hashes" json:"hashes"`
	Index  string   `mapstructure:"index" json:"index"`
}

// PythonPoetryLockEntry represents a single package entry within a Pipfile.lock file.
type PythonPoetryLockEntry struct {
	Index        string                            `mapstructure:"index" json:"index"`
	Dependencies []PythonPoetryLockDependencyEntry `json:"dependencies"`
	Extras       []PythonPoetryLockExtraEntry      `json:"extras,omitempty"`
}

type PythonPoetryLockDependencyEntry struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Optional bool     `json:"optional"`
	Markers  string   `json:"markers,omitempty"`
	Extras   []string `json:"extras,omitempty"`
}

type PythonPoetryLockExtraEntry struct {
	Name         string   `json:"name"`
	Dependencies []string `json:"dependencies"`
}

// PythonRequirementsEntry represents a single entry within a [*-]requirements.txt file.
type PythonRequirementsEntry struct {
	Name              string   `json:"name" mapstruct:"Name"`
	Extras            []string `json:"extras,omitempty" mapstruct:"Extras"`
	VersionConstraint string   `json:"versionConstraint" mapstruct:"VersionConstraint"`
	URL               string   `json:"url,omitempty" mapstruct:"URL"`
	Markers           string   `json:"markers,omitempty" mapstruct:"Markers"`
}
