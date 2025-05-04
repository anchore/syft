package golang

import (
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/unionreader"
	"github.com/kastenhq/goversion/version"
)

type extendedBuildInfo struct {
	*debug.BuildInfo
	sym            []elf.Symbol
	cryptoSettings []string
	arch           string
}

const (
	devBinaryType  binaryType = "dev"
	testBinaryType binaryType = "test"
)

type binaryType string

// scanFile scans file to try to report the Go and module versions.
func (c *goBinaryCataloger) scanFile(location file.Location, reader unionreader.UnionReader) ([]*extendedBuildInfo, binaryType, error) {
	// NOTE: multiple readers are returned to cover universal binaries, which are files
	// with more than one binary
	readers, errs := unionreader.GetReaders(reader)
	if errs != nil {
		log.WithFields("error", errs).Debug("failed to open a golang binary")
		return nil, devBinaryType, fmt.Errorf("failed to open a golang binary: %w", errs)
	}

	var builds []*extendedBuildInfo
	btyp := devBinaryType
	for _, r := range readers {
		bi, err := getBuildInfo(r)
		if err != nil {
			log.WithFields("file", location.RealPath, "error", err).Trace("unable to read golang buildinfo")

			continue
		}

		// it's possible the reader just isn't a go binary, in which case just skip it
		if bi == nil {
			continue
		}
		var sym []elf.Symbol
		if bi.Deps == nil {
			sym, _ = getSymbolsInfo(r)
			if sym != nil {
				btyp = testBinaryType
			}
		}

		v, err := getCryptoInformation(r)
		if err != nil {
			log.WithFields("file", location.RealPath, "error", err).Trace("unable to read golang version info")
			// don't skip this build info.
			// we can still catalog packages, even if we can't get the crypto information
			errs = unknown.Appendf(errs, location, "unable to read golang version info: %w", err)
		}
		arch := getGOARCH(bi.Settings)
		if arch == "" {
			arch, err = getGOARCHFromBin(r)
			if err != nil {
				log.WithFields("file", location.RealPath, "error", err).Trace("unable to read golang arch info")
				// don't skip this build info.
				// we can still catalog packages, even if we can't get the arch information
				errs = unknown.Appendf(errs, location, "unable to read golang arch info: %w", err)
			}
		}

		builds = append(builds, &extendedBuildInfo{BuildInfo: bi, sym: sym, cryptoSettings: v, arch: arch})
	}
	return builds, btyp, errs
}

func getCryptoInformation(reader io.ReaderAt) ([]string, error) {
	v, err := version.ReadExeFromReader(reader)
	if err != nil {
		return nil, err
	}

	return getCryptoSettingsFromVersion(v), nil
}

func getCryptoSettingsFromVersion(v version.Version) []string {
	cryptoSettings := []string{}
	if v.StandardCrypto {
		cryptoSettings = append(cryptoSettings, "standard-crypto")
	}
	if v.BoringCrypto {
		cryptoSettings = append(cryptoSettings, "boring-crypto")
	}
	if v.FIPSOnly {
		cryptoSettings = append(cryptoSettings, "crypto/tls/fipsonly")
	}
	return cryptoSettings
}

// getCachedChecksum just as the function name, it gets the checksum from the path with the pattern like
// GOPATH/pkg/mod/cache/download/example.com/module/@v/v1.2.3.ziphash
func getCachedChecksum(pkgDir string, name string, version string) (content string, err error) {
	checksumPath := fmt.Sprintf("%s/cache/download/%s/@v/%s.ziphash", pkgDir, name, version)
	bytes, err := os.ReadFile(checksumPath)
	content = string(bytes)
	return
}

func trimmedAsURL(name string) (url string) {
	parts := strings.Split(name, "/")
	if len(parts) >= 3 {
		versionWithFunc := parts[2]
		if idx := strings.Index(versionWithFunc, "."); idx != -1 {
			parts[2] = versionWithFunc[:idx]
		}
		url = strings.Join(parts[:3], "/")
	}
	return
}

func findVersion(basePath string) (string, error) {
	dir := filepath.Dir(basePath)
	baseName := filepath.Base(basePath)
	files, err := os.ReadDir(dir)
	if err != nil {
		return "", err
	}

	for _, fil := range files {
		if strings.HasPrefix(fil.Name(), baseName+"@") {
			parts := strings.Split(fil.Name(), "@")
			if len(parts) == 2 {
				return parts[1], nil
			}
		}
	}

	return "", fmt.Errorf("%s doesn't exist in the GO MODULES,hence no versioned path found for it", basePath)
}

// getModulesFromSymbols
func (c *goBinaryCataloger) getModulesFromSymbols(syms []elf.Symbol) (result []*debug.Module) {
	uniqueModules := make(map[string]*debug.Module)
	// FIXME using the configured not default go mod dir
	goPath := c.licenseResolver.opts.LocalModCacheDir

	for _, sym := range syms {
		url := trimmedAsURL(sym.Name)
		// the sym is not a mark of third-party function
		if len(url) == 0 {
			continue
		}
		pathWithoutVersion := fmt.Sprintf("%s/%s", goPath, url)
		Version, err := findVersion(pathWithoutVersion)
		// No such module
		if len(Version) == 0 || err != nil {
			continue
		}

		key := fmt.Sprintf("%s %s", url, Version)
		checksum, _ := getCachedChecksum(goPath, url, Version)
		uniqueModules[key] = &debug.Module{
			Path:    url,
			Version: Version,
			Sum:     checksum,
			Replace: nil,
		}
	}

	for _, v := range uniqueModules {
		result = append(result, v)
	}
	return result
}

// getSymbolsInfo is used to parse the dependencies in a test binary with the help of Go Module cache
func getSymbolsInfo(r io.ReaderAt) (result []elf.Symbol, err error) {
	f, err := elf.NewFile(r)
	if err != nil {
		err = fmt.Errorf("malformed test binary file")
	}
	defer func(f *elf.File) {
		err = f.Close()
	}(f)

	result, err = f.Symbols()
	if err != nil {
		err = fmt.Errorf("error when parsing the symbols of the binary")
	}

	/**/
	return
}

func getBuildInfo(r io.ReaderAt) (bi *debug.BuildInfo, err error) {
	defer func() {
		if r := recover(); r != nil {
			// this can happen in cases where a malformed binary is passed in can be initially parsed, but not
			// used without error later down the line. This is the case with :
			// https://github.com/llvm/llvm-project/blob/llvmorg-15.0.6/llvm/test/Object/Inputs/macho-invalid-dysymtab-bad-size
			err = fmt.Errorf("recovered from panic: %v", r)
		}
	}()
	bi, err = buildinfo.Read(r)

	// note: the stdlib does not export the error we need to check for
	if err != nil {
		if err.Error() == "not a Go executable" {
			// since the cataloger can only select executables and not distinguish if they are a go-compiled
			// binary, we should not show warnings/logs in this case. For this reason we nil-out err here.
			err = nil
			return
		}
		// in this case we could not read the or parse the file, but not explicitly because it is not a
		// go-compiled binary (though it still might be).
		return
	}
	return
}
