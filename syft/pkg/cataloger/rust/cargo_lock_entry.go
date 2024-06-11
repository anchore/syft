package rust

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/spdx/tools-golang/spdx"
	"io"
	"net/http"
	"os"
	"strings"
)

type RustCargoLockEntry struct {
	CargoLockVersion int      `toml:"-" json:"-"`
	Name             string   `toml:"name" json:"name"`
	Version          string   `toml:"version" json:"version"`
	Source           string   `toml:"source" json:"source"`
	Checksum         string   `toml:"checksum" json:"checksum"`
	Dependencies     []string `toml:"dependencies" json:"dependencies"`
}

// GetChecksumType This exists, to made adopting new potential cargo.lock versions easier
func (r *RustCargoLockEntry) GetChecksumType() spdx.ChecksumAlgorithm {
	//Cargo currently always uses Sha256: https://github.com/rust-lang/cargo/blob/a9ee3e82b57df019dfc0385f844bc6928150ee63/src/cargo/sources/registry/download.rs#L125
	return spdx.SHA256
}

// GetPrefix get {path} for https://doc.rust-lang.org/cargo/reference/registry-index.html
func (r *RustCargoLockEntry) GetPrefix() string {
	switch len(r.Name) {
	case 0:
		return ""
	case 1:
		return fmt.Sprintf("1/%s", r.Name[0:1])
	case 2:
		return fmt.Sprintf("2/%s", r.Name[0:2])
	case 3:
		return fmt.Sprintf("3/%s", r.Name[0:1])
	default:
		return fmt.Sprintf("%s/%s", r.Name[0:2], r.Name[2:4])
	}
}

func (r *RustCargoLockEntry) GetDownloadLink() (url string, isLocalFile bool, err error) {
	sourceId, err := GetSourceId(r)
	if err != nil {
		return "", false, err
	}
	isLocalFile = sourceId.IsLocalSource()
	var repoConfig *RepositoryConfig = nil
	repoConfig, err = sourceId.GetConfig()
	if err != nil {
		return "", isLocalFile, err
	}
	return r.getDownloadLink(repoConfig.Download), isLocalFile, err
}

func (r *RustCargoLockEntry) getDownloadLink(url string) string {
	if !strings.Contains(url, Crate) &&
		!strings.Contains(url, Version) &&
		!strings.Contains(url, Prefix) &&
		!strings.Contains(url, LowerPrefix) &&
		!strings.Contains(url, Sha256Checksum) {
		return url + fmt.Sprintf("/%s/%s/download", r.Name, r.Version)
	}

	var link = url
	link = strings.ReplaceAll(link, Crate, r.Name)
	link = strings.ReplaceAll(link, Version, r.Version)
	link = strings.ReplaceAll(link, Prefix, r.GetPrefix())
	link = strings.ReplaceAll(link, LowerPrefix, strings.ToLower(r.GetPrefix()))
	link = strings.ReplaceAll(link, Sha256Checksum, r.Checksum)
	return link
}
func (r *RustCargoLockEntry) GetIndexPath() string {
	return fmt.Sprintf("%s/%s", strings.ToLower(r.GetPrefix()), strings.ToLower(r.Name))
}
func (r *RustCargoLockEntry) GetDownloadSha() []byte {
	var link, isLocal, err = r.GetDownloadLink()
	if err != nil {
		return nil
	}

	var content []byte
	if !isLocal {
		var resp *http.Response
		resp, err = http.Get(link)
		if err != nil {
			return nil
		}

		content, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil
		}
	} else {
		content, err = os.ReadFile(link)
		if err != nil {
			return nil
		}
	}

	var hash = sha256.New().Sum(content)
	return hash
}
func (r *RustCargoLockEntry) GetIndexContent() ([]DependencyInformation, []error) {
	var deps []DependencyInformation
	var sourceID, err = GetSourceId(r)
	if err != nil {
		return deps, []error{err}
	}
	var content []byte
	var errors []error
	content, err = sourceID.GetPath(r.GetIndexPath())
	for _, v := range bytes.Split(content, []byte("\n")) {
		var depInfo = DependencyInformation{
			StructVersion: 1,
		}
		err = json.Unmarshal(v, &depInfo)
		if err == nil {
			deps = append(deps, depInfo)
		} else {
			errors = append(errors, err)
		}
	}
	return deps, errors
}
