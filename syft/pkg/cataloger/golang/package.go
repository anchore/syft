package golang

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/source"
)

const DefaultGoProxy = "https://proxy.golang.org"

// this to be removed when we enable remote retrieval of go modules
const disableRemotePackage = true

func newGoBinaryPackage(dep *debug.Module, mainModule, goVersion, architecture string, buildSettings map[string]string, locations ...source.Location) pkg.Package {
	if dep.Replace != nil {
		dep = dep.Replace
	}

	p := pkg.Package{
		Name:         dep.Path,
		Version:      dep.Version,
		Licenses:     goLicenses(dep.Path, dep.Version),
		PURL:         packageURL(dep.Path, dep.Version),
		Language:     pkg.Go,
		Type:         pkg.GoModulePkg,
		Locations:    source.NewLocationSet(locations...),
		MetadataType: pkg.GolangBinMetadataType,
		Metadata: pkg.GolangBinMetadata{
			GoCompiledVersion: goVersion,
			H1Digest:          dep.Sum,
			Architecture:      architecture,
			BuildSettings:     buildSettings,
			MainModule:        mainModule,
		},
	}

	p.SetID()

	return p
}

func packageURL(moduleName, moduleVersion string) string {
	// source: https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#golang
	// note: "The version is often empty when a commit is not specified and should be the commit in most cases when available."

	re := regexp.MustCompile(`(/)[^/]*$`)
	fields := re.Split(moduleName, -1)
	if len(fields) == 0 {
		return ""
	}
	namespace := fields[0]
	name := strings.TrimPrefix(strings.TrimPrefix(moduleName, namespace), "/")

	if name == "" {
		// this is a "short" url (with no namespace)
		name = namespace
		namespace = ""
	}

	// The subpath is used to point to a subpath inside a package (e.g. pkg:golang/google.golang.org/genproto#googleapis/api/annotations)
	subpath := "" // TODO: not implemented

	return packageurl.NewPackageURL(
		packageurl.TypeGolang,
		namespace,
		name,
		moduleVersion,
		nil,
		subpath,
	).ToString()
}

func goLicenses(moduleName, moduleVersion string) []string {
	fsys, err := getModule(moduleName, moduleVersion, DefaultGoProxy)
	if err != nil {
		return nil
	}
	return licenses.ScanLicenses(fsys)
}

func getModule(module, version, proxy string) (fs.FS, error) {
	// first see if we have it locally
	goPath := os.Getenv("GOPATH")
	if goPath != "" {
		modPath := filepath.Join(goPath, "pkg", "mod", fmt.Sprintf("%s@%s", module, version))
		if fi, err := os.Stat(modPath); err == nil && fi != nil && fi.IsDir() {
			modFS := os.DirFS(modPath)
			return modFS, nil
		}
	}

	if disableRemotePackage {
		return nil, fmt.Errorf("module %s@%s not found locally", module, version)
	}

	// we could not get it locally, so get it from the proxy, but only if network is enabled

	// get the module zip
	resp, err := http.Get(fmt.Sprintf("%s/%s/@v/%s.zip", proxy, module, version))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get module zip: %s", resp.Status)
	}
	// read the zip
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return zip.NewReader(bytes.NewReader(b), resp.ContentLength)
}
