package pkg

import (
	"sort"

	"github.com/scylladb/go-set/strset"
)

type CondaPathData struct {
	Path           string `json:"_path"`
	PathType       string `json:"path_type"`
	SHA256         string `json:"sha256"`
	SHA256InPrefix string `json:"sha256_in_prefix"`
	SizeInBytes    int64  `json:"size_in_bytes"`
}

type CondaPathsData struct {
	PathsVersion int             `json:"paths_version"`
	Paths        []CondaPathData `json:"paths"`
}

type CondaLink struct {
	Source string `json:"source"`
	Type   int    `json:"type"`
}

type CondaMetaPackage struct {
	Arch                string          `json:"arch,omitempty"`
	Name                string          `json:"name"`
	Version             string          `json:"version"`
	Build               string          `json:"build"`
	BuildNumber         int             `json:"build_number"`
	Channel             string          `json:"channel,omitempty"`
	Subdir              string          `json:"subdir,omitempty"`
	Noarch              string          `json:"noarch,omitempty"`
	License             string          `json:"license,omitempty"`
	LicenseFamily       string          `json:"license_family,omitempty"`
	MD5                 string          `json:"md5,omitempty"`
	SHA256              string          `json:"sha256,omitempty"`
	Size                int64           `json:"size,omitempty"`
	Timestamp           int64           `json:"timestamp,omitempty"`
	Filename            string          `json:"fn,omitempty"`
	URL                 string          `json:"url,omitempty"`
	ExtractedPackageDir string          `json:"extracted_package_dir,omitempty"`
	Depends             []string        `json:"depends,omitempty"`
	Files               []string        `json:"files,omitempty"`
	PathsData           *CondaPathsData `json:"paths_data,omitempty"`
	Link                *CondaLink      `json:"link,omitempty"`
}

func (m CondaMetaPackage) OwnedFiles() (result []string) {
	s := strset.New()
	for _, f := range m.Files {
		if f != "" {
			s.Add(f)
		}
	}
	result = s.List()
	sort.Strings(result)
	return result
}
