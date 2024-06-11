package rust

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
	"github.com/pelletier/go-toml/v2"
	"github.com/spdx/tools-golang/spdx"
)

// For JSON naming purposes, it is important, that the name stays the same here!

//revive:disable:exported
//goland:noinspection GoNameStartsWithPackageName
type RustCargoLockEntry pkg.RustCargoLockEntry

//revive:enable:exported

func (r *RustCargoLockEntry) ToPackageID() PackageID {
	return PackageID{
		Name:    r.Name,
		Version: r.Version,
	}
}

// GetChecksumType This exists, to made adopting new potential cargo.lock versions easier
func (r *RustCargoLockEntry) GetChecksumType() spdx.ChecksumAlgorithm {
	// Cargo currently always uses Sha256: https://github.com/rust-lang/cargo/blob/a9ee3e82b57df019dfc0385f844bc6928150ee63/src/cargo/sources/registry/download.rs#L125
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
	sourceID, err := r.getSourceID()
	if err != nil {
		return "", false, err
	}
	isLocalFile = sourceID.IsLocalSource()
	repoConfig, err := sourceID.GetConfig()
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
func (r *RustCargoLockEntry) GetIndexContent() ([]DependencyInformation, []error) {
	var deps []DependencyInformation
	var sourceID, err = r.getSourceID()
	if err != nil {
		return deps, []error{err}
	}
	var content []byte
	var errors []error
	content, err = sourceID.GetPath(r.GetIndexPath())
	if err != nil {
		return deps, []error{err}
	}
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

var GeneratedInformation = make(map[PackageID]*outerGeneratedDepInfo)

func (r *RustCargoLockEntry) GetGeneratedInformation() (GeneratedDepInfo, error) {
	genDepInfo, ok := GeneratedInformation[r.ToPackageID()]
	if ok {
		var generatedDepInfoInner GeneratedDepInfo
		genDepInfo.mutex.Lock()
		generatedDepInfoInner = genDepInfo.GeneratedDepInfo
		log.Debugf("Got cached generated information for %s-%s", r.Name, r.Version)
		genDepInfo.mutex.Unlock()
		return generatedDepInfoInner, nil
	}
	return r.getGeneratedInformationUncached()
}

func (r *RustCargoLockEntry) getContent() ([]byte, string, error) {
	var content []byte
	var link, isLocal, err = r.GetDownloadLink()
	if err != nil {
		return content, link, err
	}
	log.Tracef("got download link of: link: %s, local: %t", link, isLocal)

	if !isLocal {
		var resp *http.Response
		resp, err = http.Get(link) //#nosec G107 -- This is a request with a variable url, but due to the design it has to be this way.
		if err != nil {
			return content, link, err
		}

		content, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return content, link, err
		}
	} else {
		content, err = os.ReadFile(link)
		if err != nil {
			return content, link, err
		}
	}
	log.Tracef("got content for: link: %s, local: %t", link, isLocal)
	return content, link, nil
}

func (r *RustCargoLockEntry) getGeneratedInformationUncached() (GeneratedDepInfo, error) {
	log.Tracef("Generating information for %s-%s", r.Name, r.Version)
	genDepInfo := &outerGeneratedDepInfo{
		mutex: sync.Mutex{},
		GeneratedDepInfo: GeneratedDepInfo{
			Licenses: make([]string, 0),
		},
	}
	GeneratedInformation[r.ToPackageID()] = genDepInfo

	genDepInfo.mutex.Lock()
	content, link, err := r.getContent()
	genDepInfo.DownloadLink = link
	if err != nil {
		delete(GeneratedInformation, r.ToPackageID())
		genDepInfo.mutex.Unlock()
		return genDepInfo.GeneratedDepInfo, err
	}

	genDepInfo.downloadSha = sha256.Sum256(content)
	hexHash := hex.EncodeToString(genDepInfo.downloadSha[:])
	log.Tracef("got hash: %s (%s expected) %t", hexHash, r.Checksum, hexHash == r.Checksum)

	gzReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		delete(GeneratedInformation, r.ToPackageID())
		genDepInfo.mutex.Unlock()
		return genDepInfo.GeneratedDepInfo, err
	}
	tarReader := tar.NewReader(gzReader)
	log.Tracef("Got tar-reader: %s-%s", r.Name, r.Version)

	for {
		next, err := tarReader.Next()
		if err != nil {
			_ = gzReader.Close()
			delete(GeneratedInformation, r.ToPackageID())
			genDepInfo.mutex.Unlock()
			log.Tracef("Tar reader error for %s-%s: %s", r.Name, r.Version, err)
			return genDepInfo.GeneratedDepInfo, err
		}
		if next.Name == r.Name+"-"+r.Version+"/Cargo.toml" {
			log.Tracef("Got Cargo.toml for %s-%s", r.Name, r.Version)
			cargoTomlBytes, err := io.ReadAll(tarReader)
			if err != nil {
				_ = gzReader.Close()
				delete(GeneratedInformation, r.ToPackageID())
				genDepInfo.mutex.Unlock()
				return genDepInfo.GeneratedDepInfo, err
			}

			var cargoToml cargoToml
			err = toml.Unmarshal(cargoTomlBytes, &cargoToml)
			if err != nil {
				_ = gzReader.Close()
				delete(GeneratedInformation, r.ToPackageID())
				genDepInfo.mutex.Unlock()
				return genDepInfo.GeneratedDepInfo, err
			}
			log.Tracef("Got Deserialized Cargo.toml for %s-%s: %s", r.Name, r.Version, cargoToml.Package.License)

			genDepInfo.Licenses = append(genDepInfo.Licenses, cargoToml.Package.License)
			var generatedInfoInner = genDepInfo.GeneratedDepInfo
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
