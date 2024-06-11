package rust

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/anchore/syft/internal/log"
	"github.com/pelletier/go-toml/v2"
	"github.com/spdx/tools-golang/spdx"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

//goland:noinspection GoNameStartsWithPackageName
type RustCargoLockEntry struct {
	CargoLockVersion int `toml:"-" json:"-"`
	PackageID        `toml:"-" json:"-"`
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
	sourceID, err := getSourceId(r)
	if err != nil {
		return "", false, err
	}
	isLocalFile = sourceID.IsLocalSource()
	var repoConfig *repositoryConfig = nil
	repoConfig, err = sourceID.GetConfig()
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
		return fmt.Sprintf("%s/%s/%s/download", url, r.Name, r.Version)
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
	info, err := r.GetGeneratedInformation()
	if err != nil {
		return nil
	}
	return info.downloadSha[:]
}
func (r *RustCargoLockEntry) GetIndexContent() ([]dependencyInformation, []error) {
	var deps []dependencyInformation
	var sourceID, err = getSourceId(r)
	if err != nil {
		return deps, []error{err}
	}
	var content []byte
	var errors []error
	content, err = sourceID.GetPath(r.GetIndexPath())
	for _, v := range bytes.Split(content, []byte("\n")) {
		var depInfo = dependencyInformation{
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

var GeneratedInformation = make(map[PackageID]*outerGeneratedDepInfo)

func (r *RustCargoLockEntry) GetGeneratedInformation() (generatedDepInfo, error) {
	genDepInfo, ok := GeneratedInformation[r.PackageID]
	if ok {
		var generatedDepInfoInner generatedDepInfo
		genDepInfo.mutex.Lock()
		generatedDepInfoInner = genDepInfo.generatedDepInfo
		log.Debugf("Got cached generated information for %s-%s", r.Name, r.Version)
		genDepInfo.mutex.Unlock()
		return generatedDepInfoInner, nil
	} else {
		log.Tracef("Generating information for %s-%s", r.Name, r.Version)
		genDepInfo = &outerGeneratedDepInfo{
			mutex: sync.Mutex{},
			generatedDepInfo: generatedDepInfo{
				Licenses: make([]string, 0),
			},
		}
		GeneratedInformation[r.PackageID] = genDepInfo
	}

	genDepInfo.mutex.Lock()
	GeneratedInformation[r.PackageID] = genDepInfo
	var link, isLocal, err = r.GetDownloadLink()
	genDepInfo.DownloadLink = link
	GeneratedInformation[r.PackageID] = genDepInfo
	if err != nil {
		delete(GeneratedInformation, r.PackageID)
		genDepInfo.mutex.Unlock()
		return genDepInfo.generatedDepInfo, err
	}
	log.Tracef("got download link of: link: %s, local: %t", link, isLocal)

	var content []byte
	if !isLocal {
		var resp *http.Response
		resp, err = http.Get(link)
		if err != nil {
			delete(GeneratedInformation, r.PackageID)
			genDepInfo.mutex.Unlock()
			return genDepInfo.generatedDepInfo, err
		}

		content, err = io.ReadAll(resp.Body)
		if err != nil {
			delete(GeneratedInformation, r.PackageID)
			genDepInfo.mutex.Unlock()
			return genDepInfo.generatedDepInfo, err
		}
	} else {
		content, err = os.ReadFile(link)
		if err != nil {
			delete(GeneratedInformation, r.PackageID)
			genDepInfo.mutex.Unlock()
			return genDepInfo.generatedDepInfo, err
		}
	}
	log.Tracef("got content for: link: %s, local: %t", link, isLocal)

	genDepInfo.downloadSha = sha256.Sum256(content)
	hexHash := hex.EncodeToString(genDepInfo.downloadSha[:])
	log.Tracef("got hash: %s (%s expected) %t", hexHash, r.Checksum, hexHash == r.Checksum)
	GeneratedInformation[r.PackageID] = genDepInfo

	gzReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		delete(GeneratedInformation, r.PackageID)
		genDepInfo.mutex.Unlock()
		return genDepInfo.generatedDepInfo, err
	}
	tarReader := tar.NewReader(gzReader)
	log.Tracef("Got tar-reader: %s-%s", r.Name, r.Version)

	for {
		next, err := tarReader.Next()
		if err != nil {
			delete(GeneratedInformation, r.PackageID)
			genDepInfo.mutex.Unlock()
			log.Tracef("Tar reader error for %s-%s: %s", r.Name, r.Version, err)
			return genDepInfo.generatedDepInfo, err
		}
		switch next.Name {
		case r.Name + "-" + r.Version + "/Cargo.toml":
			log.Tracef("Got Cargo.toml for %s-%s", r.Name, r.Version)
			cargoTomlBytes, err := io.ReadAll(tarReader)
			if err != nil {
				delete(GeneratedInformation, r.PackageID)
				genDepInfo.mutex.Unlock()
				return genDepInfo.generatedDepInfo, err
			}

			var cargoToml cargoToml
			err = toml.Unmarshal(cargoTomlBytes, &cargoToml)
			if err != nil {
				delete(GeneratedInformation, r.PackageID)
				genDepInfo.mutex.Unlock()
				return genDepInfo.generatedDepInfo, err
			}
			log.Tracef("Got Deserialized Cargo.toml for %s-%s: %s", r.Name, r.Version, cargoToml.Package.License)

			genDepInfo.Licenses = append(genDepInfo.Licenses, cargoToml.Package.License)
			GeneratedInformation[r.PackageID] = genDepInfo
			var generatedInfoInner = genDepInfo.generatedDepInfo
			genDepInfo.mutex.Unlock()
			return generatedInfoInner, nil
		}
	}
}

func (r *RustCargoLockEntry) GetLicenseInformation() []string {
	info, err := r.GetGeneratedInformation()
	if err != nil {
		return make([]string, 0)
	}
	return info.Licenses
}
