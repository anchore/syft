package golang

import (
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"io"
	"io/fs"
	"runtime/debug"
	"strings"

	"github.com/anchore/syft/internal"
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
			sym, err = getSymbolsInfo(r)
			if err != nil {
				log.WithFields("file", location.RealPath, "error", err).Trace("unable to read golang symtab")
				continue
			}
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
// $GOPATH/pkg/mod/cache/download/example.com/module/@v/v1.2.3.ziphash
func getCachedChecksum(pkgDir fs.FS, name string, version string) (content string, err error) {
	var res string
	err = fs.WalkDir(pkgDir, ".", func(filePath string, _ fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error when walking down the dir to find %s", name)
		}
		if strings.HasPrefix(filePath, version+".ziphash") {
			rdr, err0 := pkgDir.Open(filePath)
			if err0 != nil {
				log.Debugf("error opening ziphash file %s: %v", filePath, err)
				return err0
			}
			defer internal.CloseAndLogError(rdr, filePath)
			var bytes []byte
			reader := file.NewLocationReadCloser(file.NewLocation(filePath), rdr)
			bytes, _ = io.ReadAll(reader)
			if len(bytes) != 0 {
				res = string(bytes)
			}
		}
		return nil
	})
	if res == "" {
		return "", fmt.Errorf("no checksum for %s@%s", name, version)
	}
	return res, err
}

func trimmedAsURL(name string) (urlDir string, urlName string) {
	parts := strings.Split(name, "/")
	if len(parts) >= 3 {
		versionWithFunc := parts[2]
		if idx := strings.Index(versionWithFunc, "."); idx != -1 {
			parts[2] = versionWithFunc[:idx]
		}
		urlDir = strings.Join(parts[:2], "/")
		urlName = parts[2]
	}
	return
}

func findVersion(basePath fs.FS, baseName string) (string, error) {
	var res string
	err := fs.WalkDir(basePath, ".", func(filePath string, _ fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("error when walking down the dir to find %s", baseName)
		}

		if strings.HasPrefix(filePath, baseName) {
			parts := strings.Split(filePath, "@")
			if len(parts) == 2 {
				res = strings.Split(parts[1], "/")[0]
				return nil
			}
		}
		return nil
	})
	if res == "" {
		return "", fmt.Errorf("%s doesn't exist in the Go Modules,hence no versioned path found for it", baseName)
	}
	return res, err
}

// getModulesFromSymbols is used to parse the dependencies given the symbols of a test binary with the help of Go Module cache
func (c *goBinaryCataloger) getModulesFromSymbols(syms []elf.Symbol) (result []*debug.Module) {
	uniqueModules := make(map[string]*debug.Module)
	goPath := c.licenseResolver.localModCacheDir
	if goPath == nil {
		return nil
	}
	for _, sym := range syms {
		urlDir, nameWithoutVersion := trimmedAsURL(sym.Name)
		// the sym is not a mark of third-party function
		if len(urlDir) == 0 {
			continue
		}

		dir, err := fs.Sub(goPath, urlDir)
		if err != nil {
			continue
		}
		Version, err := findVersion(dir, nameWithoutVersion)
		// No such module
		if err != nil {
			continue
		}
		modPair := fmt.Sprintf("%s/%s", urlDir, nameWithoutVersion)
		key := fmt.Sprintf("%s %s", modPair, Version)
		cachedir, err2 := fs.Sub(goPath, "cache/download/"+modPair+"/@v")
		if err2 != nil {
			continue
		}
		checksum, _ := getCachedChecksum(cachedir, modPair, Version)
		uniqueModules[key] = &debug.Module{
			Path:    fmt.Sprintf("%s/%s", urlDir, nameWithoutVersion),
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
