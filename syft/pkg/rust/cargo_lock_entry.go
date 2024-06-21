package rust

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1" //#nosec G505 G401 -- sha1 is used as a required hash function for SPDX, not a crypto function
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/pelletier/go-toml/v2"
	"github.com/spdx/tools-golang/spdx"
)

// For JSON naming purposes, it is important, that the name stays the same here!

//revive:disable:exported
//goland:noinspection GoNameStartsWithPackageName
type RustCargoLockEntry struct {
	CargoLockVersion int      `toml:"-" json:"-"`
	Name             string   `toml:"name" json:"name"`
	Version          string   `toml:"version" json:"version"`
	Source           string   `toml:"source" json:"source"`
	Checksum         string   `toml:"checksum" json:"checksum"`
	Dependencies     []string `toml:"dependencies" json:"dependencies"`
	*RegistryGeneratedInfo
	*SourceGeneratedDepInfo
}

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

func (r *RustCargoLockEntry) GetDownloadLink() (url string, isLocalFile bool, err error) {
	if r.RegistryGeneratedInfo == nil {
		return "", false, fmt.Errorf("RegistryGeneratedInfo is nil")
	}
	return r.getDownloadLink(r.RegistryGeneratedInfo.Download), r.RegistryGeneratedInfo.IsLocalFile, err
}

func (r *RustCargoLockEntry) toRegistryGeneratedDepInfo() (RegistryGeneratedInfo, error) {
	sourceID, err := r.getSourceID()
	if err != nil {
		return EmptyRegistryGeneratedDepInfo(), err
	}
	isLocalFile := sourceID.IsLocalSource()
	repoConfig, err := sourceID.GetConfig()
	if err != nil {
		return EmptyRegistryGeneratedDepInfo(), err
	}
	return RegistryGeneratedInfo{
		IsLocalFile:      isLocalFile,
		RepositoryConfig: *repoConfig,
	}, nil
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
	link = strings.ReplaceAll(link, Prefix, r.getPrefix())
	link = strings.ReplaceAll(link, LowerPrefix, strings.ToLower(r.getPrefix()))
	link = strings.ReplaceAll(link, Sha256Checksum, r.Checksum)
	return link
}

// getPrefix get {path} for https://doc.rust-lang.org/cargo/reference/registry-index.html
func (r *RustCargoLockEntry) getPrefix() string {
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

// Todo: Do we care about any metadata present in the rust repository index?
// func (r *RustCargoLockEntry) getIndexPath() string {
// 	return fmt.Sprintf("%s/%s", strings.ToLower(r.getPrefix()), strings.ToLower(r.Name))
// }
//
// func (r *RustCargoLockEntry) getIndexContent() ([]DependencyInformation, []error) {
// 	var deps []DependencyInformation
// 	var sourceID, err = r.getSourceID()
// 	if err != nil {
// 		return deps, []error{err}
// 	}
// 	var content []byte
// 	var errors []error
// 	content, err = sourceID.GetPath(r.getIndexPath())
// 	if err != nil {
// 		return deps, []error{err}
// 	}
// 	for _, v := range bytes.Split(content, []byte("\n")) {
// 		var depInfo = DependencyInformation{
// 			StructVersion: 1,
// 		}
// 		err = json.Unmarshal(v, &depInfo)
// 		if err == nil {
// 			deps = append(deps, depInfo)
// 		} else {
// 			errors = append(errors, err)
// 		}
// 	}
// 	return deps, errors
// }

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

func (r *RustCargoLockEntry) getGeneratedInformationUncached() (SourceGeneratedDepInfo, error) {
	log.Tracef("Generating information for %s-%s", r.Name, r.Version)
	genDepInfo := SourceGeneratedDepInfo{
		Licenses:       make([]string, 0),
		PathSha1Hashes: make(map[string][20]byte),
	}

	content, link, err := r.getContent()
	genDepInfo.DownloadLink = link
	if err != nil {
		return genDepInfo, err
	}

	genDepInfo.DownloadSha = sha256.Sum256(content)
	hexHash := hex.EncodeToString(genDepInfo.DownloadSha[:])
	hashMatchesChecksum := strings.EqualFold(hexHash, r.Checksum)
	log.Tracef("got hash: %s (%s expected) %t", hexHash, r.Checksum, hexHash == r.Checksum)
	if !hashMatchesChecksum {
		return genDepInfo, fmt.Errorf("hash of the downloaded Source for crate %s@%s doesn't match the stored checksum. Got %s but expected %s", r.Name, r.Version, hexHash, r.Checksum)
	}

	gzReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return genDepInfo, err
	}
	defer func(reader *gzip.Reader) {
		_ = reader.Close()
	}(gzReader)
	tarReader := tar.NewReader(gzReader)
	log.Tracef("Got tar-reader: %s-%s", r.Name, r.Version)

	for {
		next, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Tracef("Tar reader error for %s-%s: %s", r.Name, r.Version, err)
			return genDepInfo, err
		}
		content, err := io.ReadAll(tarReader)
		if err != nil {
			return genDepInfo, err
		}
		genDepInfo.PathSha1Hashes[next.Name] = sha1.Sum(content) //#nosec G505 G401 -- sha1 is used as a required hash function for SPDX, not a crypto function

		if next.Name == r.Name+"-"+r.Version+"/Cargo.toml" {
			log.Tracef("Got Cargo.toml for %s-%s", r.Name, r.Version)
			var cargoToml CargoToml
			err = toml.Unmarshal(content, &cargoToml)
			if err != nil {
				return genDepInfo, err
			}
			log.Tracef("Got Deserialized Cargo.toml for %s-%s: %s", r.Name, r.Version, cargoToml.Package.License)

			genDepInfo.CargoToml = cargoToml
			genDepInfo.Licenses = append(genDepInfo.Licenses, cargoToml.Package.License)
		}
	}
	return genDepInfo, nil
}
