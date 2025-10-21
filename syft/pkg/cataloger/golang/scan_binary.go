package golang

import (
	"debug/buildinfo"
	"debug/elf"
	"fmt"
	"io"
	"io/fs"
	"runtime/debug"
	"strings"

	"github.com/Masterminds/semver/v3"
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
	releaseBinaryType binaryType = "release"
	testBinaryType    binaryType = "test"
)

type binaryType string

// scanFile scans file to try to report the Go and module versions.
func (c *goBinaryCataloger) scanFile(location file.Location, reader unionreader.UnionReader) ([]*extendedBuildInfo, binaryType, error) {
	// NOTE: multiple readers are returned to cover universal binaries, which are files
	// with more than one binary
	readers, errs := unionreader.GetReaders(reader)
	if errs != nil {
		log.WithFields("error", errs).Debug("failed to open a golang binary")
		return nil, releaseBinaryType, fmt.Errorf("failed to open a golang binary: %w", errs)
	}

	var builds []*extendedBuildInfo
	btyp := releaseBinaryType
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
		// a test binary has no dependencies in "buildinfo", so we resort to the .symtab section (i.e. Symbols() )
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
			res, err = fetchFileContents(pkgDir, filePath)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if res == "" {
		return "", fmt.Errorf("no checksum for %s@%s", name, version)
	}
	return res, err
}

func trimmedAsURL(goPath fs.FS, name string) (urlDir string, urlName string) {
	if strings.HasPrefix(name, "vendor") {
		return "", ""
	}
	parts := strings.Split(name, "/")

	var lastIndex int
	for i, part := range parts {
		var err error
		newPart := processCaps(part)
		if !strings.EqualFold(newPart, part) {
			newPart = fmt.Sprintf("'%s'", newPart)
		}
		_, err = goPath.Open(newPart)
		if err != nil {
			lastIndex = i
			break
		}
		goPath, _ = fs.Sub(goPath, newPart)
	}

	versionWithFunc := parts[lastIndex]
	if idx := strings.Index(versionWithFunc, "."); idx != -1 {
		parts[lastIndex] = versionWithFunc[:idx]
	}
	if lastIndex != 0 {
		urlDir = strings.Join(parts[:lastIndex], "/")
	} else {
		urlDir = "."
	}
	urlName = parts[lastIndex]
	// some package contains '.' after the last slash, it's hard to tell the border between the package and its functions
	// but in the binary, this special . is encoded as %2e, so this case should be considered
	// e.g. gopkg.in/warnings%2ev0.List.Error -> gopkg.in/warnings.v0
	if strings.Contains(urlName, "%2e") {
		urlName = strings.ReplaceAll(urlName, "%2e", ".")
	}
	return urlDir, urlName
}

func trimmedAsURL2(lines map[string]string, name string) (urlDir string, urlName string) {
	if strings.HasPrefix(name, "vendor") {
		return "", ""
	}
	parts := strings.Split(name, "/")

	var lastIndex int
	for pkgName := range lines {
		if strings.HasPrefix(name, pkgName) {
			lineParts := strings.Split(pkgName, "/")
			lastIndex = len(lineParts) - 1
			break
		}
	}

	versionWithFunc := parts[lastIndex]
	if idx := strings.Index(versionWithFunc, "."); idx != -1 {
		parts[lastIndex] = versionWithFunc[:idx]
	}
	if lastIndex != 0 {
		urlDir = strings.Join(parts[:lastIndex], "/")
	} else {
		urlDir = "."
	}
	urlName = parts[lastIndex]
	return urlDir, urlName
}

func findVersionInCache(basePath fs.FS, baseName string) (string, error) {
	entries, err := fs.ReadDir(basePath, ".")
	if err != nil {
		return "", fmt.Errorf("error when surfacing dir to find %s", baseName)
	}
	var winner string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, baseName) {
			parts := strings.Split(name, "@")
			if len(parts) == 2 {
				newCandidate := strings.Split(parts[1], "/")[0]
				if len(winner) == 0 {
					winner = newCandidate
				} else {
					v1, _ := semver.NewVersion(newCandidate)
					v2, _ := semver.NewVersion(winner)
					if v1.LessThan(v2) {
						winner = newCandidate
					}
				}
			}
		}
	}
	if len(winner) == 0 {
		return "", fmt.Errorf("%s doesn't exist in the Go Modules,hence no versioned path found for it", baseName)
	}
	return winner, err
}

func fetchFileContents(basePath fs.FS, fileName string) (res string, err error) {
	rdr, err0 := basePath.Open(fileName)
	if err0 != nil {
		log.Debugf("error opening file %s: %v", fileName, err)
		return
	}
	defer internal.CloseAndLogError(rdr, fileName)
	var bytes []byte
	reader := file.NewLocationReadCloser(file.NewLocation(fileName), rdr)
	bytes, _ = io.ReadAll(reader)
	if len(bytes) != 0 {
		res = string(bytes)
	}
	return
}

func findVersionsInVendor(basePath fs.FS) (map[string]string, error) {
	res := make(map[string]string)
	entries, err := fs.ReadDir(basePath, ".")
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.EqualFold(entry.Name(), "modules.txt") {
			continue
		}
		contents, err2 := fetchFileContents(basePath, entry.Name())
		if err2 != nil || len(contents) == 0 {
			continue
		}
		lines := strings.Split(contents, "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "# ") {
				tuple := strings.Split(line, " ")
				if len(tuple) >= 3 {
					name := tuple[1]
					// see trimmedAsURL
					arrs := strings.Split(name, "/")
					name = strings.ReplaceAll(arrs[len(arrs)-1], ".", "%2e")
					namePrefix := strings.Join(arrs[:len(arrs)-1], "/")
					if len(namePrefix) != 0 {
						name = fmt.Sprintf("%s/%s", namePrefix, name)
					}
					ver := tuple[2]
					res[name] = ver
				}
			}
		}
	}
	if len(res) == 0 {
		return nil, fmt.Errorf("modules.txt doesn't exist in the Go Vendors,hence no versioned path found for it")
	}
	return res, err
}

func (c *goBinaryCataloger) getModulesInfoInCache(syms []elf.Symbol, goPath fs.FS) map[string]*debug.Module {
	uniqueModules := make(map[string]*debug.Module)
	for _, sym := range syms {
		// sym.Info is a common type in Linux, the low 4 bits represents type and the high 4 indicates binding
		// the type for 0x12 is FUNC(0x02) and the binding is GLOBAL(0x01)
		// since we seek for external dependencies, only global type symbols are needed
		if sym.Info != 0x12 {
			continue
		}
		urlDir, nameWithoutVersion := trimmedAsURL(goPath, sym.Name)
		urlDirInPath := uncapitalize(urlDir)
		nameInPath := uncapitalize(nameWithoutVersion)
		// the sym is not a mark of third-party function
		if len(urlDir) == 0 {
			continue
		}
		var modPair, modPairInPath string
		if strings.EqualFold(urlDir, ".") {
			modPair = nameWithoutVersion
			modPairInPath = nameInPath
		} else {
			modPair = fmt.Sprintf("%s/%s", urlDir, nameWithoutVersion)
			modPairInPath = fmt.Sprintf("%s/%s", urlDirInPath, nameInPath)
		}
		if _, exists := uniqueModules[modPair]; exists {
			continue
		}
		_, err := goPath.Open(urlDirInPath)
		if err != nil {
			continue
		}
		dir, _ := fs.Sub(goPath, urlDirInPath)

		Version, err := findVersionInCache(dir, nameInPath)
		// No such module
		if err != nil || len(Version) == 0 {
			continue
		}

		cachedir, err2 := fs.Sub(goPath, "cache/download/"+modPairInPath+"/@v")
		if err2 != nil {
			continue
		}
		checksum, _ := getCachedChecksum(cachedir, modPair, Version)
		uniqueModules[modPair] = &debug.Module{
			Path:    modPair,
			Version: Version,
			Sum:     checksum,
			Replace: nil,
		}
	}
	return uniqueModules
}

func uncapitalize(name string) (newName string) {
	parts := strings.Split(name, "/")
	for i, part := range parts {
		newPart := processCaps(part)
		if !strings.EqualFold(newPart, part) {
			parts[i] = fmt.Sprintf("'%s'", newPart)
		}
	}
	newName = strings.Join(parts, "/")
	return
}

func (c *goBinaryCataloger) getModulesInfoInVendor(syms []elf.Symbol, goPath fs.FS) map[string]*debug.Module {
	uniqueModules := make(map[string]*debug.Module)
	lines, err := findVersionsInVendor(goPath)
	if err != nil {
		return uniqueModules
	}

	for _, sym := range syms {
		if sym.Info != 0x12 {
			continue
		}
		urlDir, nameWithoutVersion := trimmedAsURL2(lines, sym.Name)
		// the sym is not a mark of third-party function
		if len(urlDir) == 0 {
			continue
		}
		var modPair string
		if strings.EqualFold(urlDir, ".") {
			modPair = nameWithoutVersion
		} else {
			modPair = fmt.Sprintf("%s/%s", urlDir, nameWithoutVersion)
		}
		if _, exists := uniqueModules[modPair]; exists {
			continue
		}
		var version string
		if _, exists := lines[modPair]; exists {
			version = lines[modPair]
		} else { // there's no corresponding entry in vendor/modules.txt
			continue
		}
		// see trimmedAsURL
		if strings.Contains(nameWithoutVersion, "%2e") {
			nameWithoutVersion = strings.ReplaceAll(nameWithoutVersion, "%2e", ".")
		}
		if strings.EqualFold(urlDir, ".") {
			modPair = nameWithoutVersion
		} else {
			modPair = fmt.Sprintf("%s/%s", urlDir, nameWithoutVersion)
		}
		// h1-digest/checksum is unavailable in the vendor/
		uniqueModules[modPair] = &debug.Module{
			Path:    modPair,
			Version: version,
			Sum:     "",
			Replace: nil,
		}
	}
	return uniqueModules
}

// getModulesFromSymbols is used to parse the dependencies given the symbols of a test binary with the help of Go Module cache
func (c *goBinaryCataloger) getModulesFromSymbols(syms []elf.Symbol) (result []*debug.Module) {
	uniqueModules := make(map[string]*debug.Module)
	// even though both of two options are available, we still prefer the local mod one
	// because it will find checksums
	if c.licenseResolver.opts.SearchLocalModCacheLicenses {
		goPath := c.licenseResolver.localModCacheDir
		if goPath != nil {
			uniqueModules = c.getModulesInfoInCache(syms, goPath)
		}
	} else if c.licenseResolver.opts.SearchLocalVendorLicenses {
		goPath := c.licenseResolver.localVendorDir
		if goPath != nil {
			uniqueModules = c.getModulesInfoInVendor(syms, goPath)
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
