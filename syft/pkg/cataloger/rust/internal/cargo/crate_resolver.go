package cargo

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1" //nolint:gosec  // this is not a security issue since this is only used in the context of comparing hashes.
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/anchore/syft/internal/cache"
)

type CrateInfo struct {
	DownloadLink string
	DownloadSha  string
	Licenses     []string
	CargoToml
	PathSha1Hashes map[string]string
}

type crateResolver struct {
	onlineEnabled bool
	crateCache    cache.Resolver[CrateInfo]
	http          httpGetter
}

type CargoToml struct { // nolint:revive
	Package TomlPackage `toml:"package"`
}
type TomlPackage struct {
	Description string `toml:"description"`
	Homepage    string `toml:"homepage"`
	Repository  string `toml:"repository"`
	License     string `toml:"license"`
	LicenseFile string `toml:"license-file"`
}

func newCrateResolver(onlineEnabled bool) crateResolver {
	return crateResolver{
		onlineEnabled: onlineEnabled,
		crateCache:    cache.GetResolverCachingErrors[CrateInfo]("cargo/crate", "v1"),
		http:          http.DefaultClient,
	}
}

func (r *crateResolver) resolve(entry LockEntry) (CrateInfo, error) {
	if entry.CrateInfo != nil {
		return *entry.CrateInfo, nil
	}
	if !r.onlineEnabled || entry.RegistryInfo == nil {
		return CrateInfo{}, nil
	}

	return r.crateCache.Resolve(
		entry.Source,
		sourceAdapter{
			entry:         entry,
			onlineEnabled: r.onlineEnabled,
			http:          r.http,
		}.fetch)
}

type sourceAdapter struct {
	entry         LockEntry
	onlineEnabled bool
	http          httpGetter
}

func (s sourceAdapter) fetch() (CrateInfo, error) {
	if !s.onlineEnabled {
		return CrateInfo{}, nil
	}

	entry := s.entry

	genDepInfo := CrateInfo{
		PathSha1Hashes: make(map[string]string),
	}

	content, link, err := s.fetchCargoArchiveContents()
	genDepInfo.DownloadLink = link
	if err != nil {
		return genDepInfo, err
	}

	// TODO chain stream of hasher and gzip reader instead of reading entire contents.
	genDepInfo.DownloadSha = fmt.Sprintf("%x", sha256.Sum256(content))
	hashMatchesChecksum := strings.EqualFold(genDepInfo.DownloadSha, entry.Checksum)
	if !hashMatchesChecksum {
		return genDepInfo, fmt.Errorf("hash of the downloaded Source for crate %s@%s doesn't match the stored checksum. Got %s but expected %s", entry.Name, entry.Version, genDepInfo.DownloadSha, entry.Checksum)
	}

	gzReader, err := gzip.NewReader(bytes.NewReader(content))
	if err != nil {
		return genDepInfo, err
	}
	defer func(reader *gzip.Reader) {
		_ = reader.Close()
	}(gzReader)
	tarReader := tar.NewReader(gzReader)

	for {
		next, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return genDepInfo, fmt.Errorf("unable to read tar file for rust cargo package %s@%s: %w", entry.Name, entry.Version, err)
		}

		// TODO: stream this, don't store it all in memory
		c, err := io.ReadAll(tarReader)
		if err != nil {
			return genDepInfo, err
		}

		genDepInfo.PathSha1Hashes[next.Name] = fmt.Sprintf("%x", sha1.Sum(c)) //nolint:gosec  // this is not a security issue since this is only used in the context of comparing hashes.

		if next.Name == entry.Name+"-"+entry.Version+"/Cargo.toml" {
			var cargoToml CargoToml
			err = toml.Unmarshal(c, &cargoToml)
			if err != nil {
				return genDepInfo, err
			}

			genDepInfo.CargoToml = cargoToml
			genDepInfo.Licenses = append(genDepInfo.Licenses, cargoToml.Package.License)
		}
	}
	return genDepInfo, nil
}

func (s sourceAdapter) fetchCargoArchiveContents() ([]byte, string, error) {
	var content []byte
	var err error
	var link, isLocal = s.entry.cargoArchiveDownloadLink()
	if link == "" {
		return content, link, nil
	}

	if !isLocal {
		var resp *http.Response
		resp, err = s.http.Get(link) //nolint:gosec  // this is required functionality
		if err != nil {
			return content, link, err
		}

		// TODO stream contents instead of reading all of it
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
	return content, link, nil
}
