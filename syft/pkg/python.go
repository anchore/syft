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
	Name                 string                     `json:"name" mapstructure:"Name"`
	Version              string                     `json:"version" mapstructure:"Version"`
	Author               string                     `json:"author" mapstructure:"Author"`
	AuthorEmail          string                     `json:"authorEmail" mapstructure:"AuthorEmail"`
	Platform             string                     `json:"platform" mapstructure:"Platform"`
	Files                []PythonFileRecord         `json:"files,omitempty"`
	SitePackagesRootPath string                     `json:"sitePackagesRootPath"`
	TopLevelPackages     []string                   `json:"topLevelPackages,omitempty"`
	DirectURLOrigin      *PythonDirectURLOriginInfo `json:"directUrlOrigin,omitempty"`
	RequiresPython       string                     `json:"requiresPython,omitempty" mapstructure:"RequiresPython"`
	RequiresDist         []string                   `json:"requiresDist,omitempty" mapstructure:"RequiresDist"`
	ProvidesExtra        []string                   `json:"providesExtra,omitempty" mapstructure:"ProvidesExtra"`
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
	Name              string   `json:"name" mapstructure:"Name"`
	Extras            []string `json:"extras,omitempty" mapstructure:"Extras"`
	VersionConstraint string   `json:"versionConstraint" mapstructure:"VersionConstraint"`
	URL               string   `json:"url,omitempty" mapstructure:"URL"`
	Markers           string   `json:"markers,omitempty" mapstructure:"Markers"`
}

type PythonUvLockDependencyEntry struct {
	Name     string   `json:"name"`
	Optional bool     `json:"optional"`
	Markers  string   `json:"markers,omitempty"`
	Extras   []string `json:"extras,omitempty"`
}

type PythonUvLockExtraEntry struct {
	Name         string   `json:"name"`
	Dependencies []string `json:"dependencies"`
}

type PythonUvLockEntry struct {
	Index        string                        `mapstructure:"index" json:"index"`
	Dependencies []PythonUvLockDependencyEntry `json:"dependencies"`
	Extras       []PythonUvLockExtraEntry      `json:"extras,omitempty"`
}
