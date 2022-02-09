package pkg

import (
	"fmt"
	"sort"

	"github.com/anchore/syft/syft/linux"

	"github.com/anchore/packageurl-go"
	"github.com/scylladb/go-set/strset"
)

var (
	_ FileOwner     = (*PythonPackageMetadata)(nil)
	_ urlIdentifier = (*PythonPackageMetadata)(nil)
)

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

// PythonPackageMetadata represents all captured data for a python egg or wheel package.
type PythonPackageMetadata struct {
	Name                 string                     `json:"name" mapstruct:"Name"`
	Version              string                     `json:"version" mapstruct:"Version"`
	License              string                     `json:"license" mapstruct:"License"`
	Author               string                     `json:"author" mapstruct:"Author"`
	AuthorEmail          string                     `json:"authorEmail" mapstruct:"Authoremail"`
	Platform             string                     `json:"platform" mapstruct:"Platform"`
	Files                []PythonFileRecord         `json:"files,omitempty"`
	SitePackagesRootPath string                     `json:"sitePackagesRootPath"`
	TopLevelPackages     []string                   `json:"topLevelPackages,omitempty"`
	DirectURLOrigin      *PythonDirectURLOriginInfo `json:"directUrlOrigin,omitempty"`
}

type DirectURLOrigin struct {
	URL         string      `json:"url"`
	VCSInfo     VCSInfo     `json:"vcs_info"`
	ArchiveInfo ArchiveInfo `json:"archive_info"`
	DirInfo     DirInfo     `json:"dir_info"`
}

type DirInfo struct {
	Editable bool `json:"editable"`
}

type ArchiveInfo struct {
	Hash string `json:"hash"`
}

type VCSInfo struct {
	CommitID          string `json:"commit_id"`
	VCS               string `json:"vcs"`
	RequestedRevision string `json:"requested_revision"`
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

func (m PythonPackageMetadata) PackageURL(_ *linux.Release) string {
	// generate a purl from the package data
	pURL := packageurl.NewPackageURL(
		packageurl.TypePyPi,
		"",
		m.Name,
		m.Version,
		m.purlQualifiers(),
		"")

	return pURL.ToString()
}

func (m PythonPackageMetadata) purlQualifiers() packageurl.Qualifiers {
	q := packageurl.Qualifiers{}
	if m.DirectURLOrigin != nil {
		q = append(q, m.DirectURLOrigin.vcsURLQualifier()...)
	}
	return q
}

func (p PythonDirectURLOriginInfo) vcsURLQualifier() packageurl.Qualifiers {
	if p.VCS != "" {
		// Taken from https://github.com/package-url/purl-spec/blob/master/PURL-SPECIFICATION.rst#known-qualifiers-keyvalue-pairs
		// packageurl-go still doesn't support all qualifier names
		return packageurl.Qualifiers{{Key: PURLQualifierVCSURL, Value: fmt.Sprintf("%s+%s@%s", p.VCS, p.URL, p.CommitID)}}
	}
	return nil
}
