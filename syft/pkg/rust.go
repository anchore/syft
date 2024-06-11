package pkg

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/anchore/syft/syft/pkg/cataloger/rust"
	"github.com/spdx/tools-golang/spdx"
	"io"
	"net/http"
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

type RustBinaryAuditEntry struct {
	Name    string `toml:"name" json:"name"`
	Version string `toml:"version" json:"version"`
	Source  string `toml:"source" json:"source"`
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

func (r *RustCargoLockEntry) GetDownloadLink() (string, error) {
	var sourceId, err = rust.GetSourceId(r)
	if err != nil {
		return "", err
	}
	var repoConfig *rust.RepositoryConfig = nil
	repoConfig, err = sourceId.GetConfig()
	if err != nil {
		return "", err
	}
	return r.getDownloadLink(repoConfig.Download), err
}

func (r *RustCargoLockEntry) getDownloadLink(url string) string {
	const Crate = "{crate}"
	const Version = "{version}"
	const Prefix = "{prefix}"
	const LowerPrefix = "{lowerprefix}"
	const Sha256Checksum = "{sha256-checksum}"
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
	var link, err = r.GetDownloadLink()
	if err != nil {
		return nil
	}
	var resp *http.Response
	resp, err = http.Get(link)
	if err != nil {
		return nil
	}

	var content []byte
	content, err = io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var hash = sha256.New().Sum(content)
	return hash
}
func (r *RustCargoLockEntry) GetIndexContent() ([]rust.DependencyInformation, []error) {
	var deps []rust.DependencyInformation
	var sourceID, err = rust.GetSourceId(r)
	if err != nil {
		return deps, []error{err}
	}
	var content []byte
	var errors []error
	content, err = sourceID.GetPath(r.GetIndexPath())
	for _, v := range bytes.Split(content, []byte("\n")) {
		var depInfo = rust.DependencyInformation{
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
