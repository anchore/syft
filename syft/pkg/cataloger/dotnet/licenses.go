package dotnet

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg"
	"github.com/scylladb/go-set/strset"
)

type nugetLicenses struct {
	opts                     CatalogerConfig
	localNuGetCacheResolvers []file.Resolver
	lowerLicenseFileNames    *strset.Set
}

func newNugetLicenses(opts CatalogerConfig) nugetLicenses {
	return nugetLicenses{
		opts:                     opts,
		localNuGetCacheResolvers: nil,
		lowerLicenseFileNames:    strset.New(lowercaseLicenseFiles()...),
	}
}

func lowercaseLicenseFiles() []string {
	fileNames := licenses.FileNames()
	for i := range fileNames {
		fileNames[i] = strings.ToLower(fileNames[i])
	}
	return fileNames
}

func appendNewLicenses(licenses []pkg.License, potentiallyNew ...pkg.License) []pkg.License {
	if len(potentiallyNew) > 0 {
		for _, lic := range potentiallyNew {
			found := false
			for _, known := range licenses {
				if known.Value == lic.Value &&
					known.SPDXExpression == lic.SPDXExpression &&
					known.Type == lic.Type {
					found = true
					break
				}
			}
			if !found {
				licenses = append(licenses, lic)
			}
		}
	}
	return licenses
}

func (c *nugetLicenses) getLicenses(moduleName, moduleVersion string, resolver file.Resolver) ([]pkg.License, error) {
	licenses := []pkg.License{}

	if c.opts.SearchLocalLicenses {
		if c.localNuGetCacheResolvers == nil {
			// Try to determine NuGet package folder resolvers
			c.localNuGetCacheResolvers = getLocalNugetFolderResolvers(resolver)
		}

		// if we're running against a directory on the filesystem, it may not include the
		// user's homedir, so we defer to using the localModCacheResolver
		for _, resolver := range c.localNuGetCacheResolvers {
			if lics, err := c.findLocalLicenses(resolver, moduleSearchGlob(moduleName, moduleVersion)); err == nil {
				licenses = appendNewLicenses(licenses, lics...)
			}
		}
	}

	if c.opts.SearchRemoteLicenses {
		if lics, err := c.findRemoteLicenses(moduleName, moduleVersion); err == nil {
			licenses = appendNewLicenses(licenses, lics...)
		}
	}

	var err error
	if len(licenses) == 0 {
		err = errors.New("no licenses found")
	}
	return licenses, err
}

func (c *nugetLicenses) findLocalLicenses(resolver file.Resolver, globMatch string) (out []pkg.License, err error) {
	out = make([]pkg.License, 0)
	if resolver == nil {
		return
	}

	locations, err := resolver.FilesByGlob(globMatch)
	if err != nil {
		return nil, err
	}

	for _, l := range locations {
		fileName := filepath.Base(l.RealPath)
		if c.lowerLicenseFileNames.Has(strings.ToLower(fileName)) {
			contents, err := resolver.FileContentsByLocation(l)
			if err != nil {
				return nil, err
			}

			parsed, err := licenses.Parse(contents, l)
			contents.Close()

			if err != nil {
				return nil, err
			}

			out = append(out, parsed...)
		}
	}

	return
}

// File is used in the NuSpec struct
type File struct {
	Source string `xml:"src,attr"`
	Target string `xml:"target,attr"`
}

// Dependency is used in the NuSpec struct
type Dependency struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

// NuSpec represents a .nuspec XML file found in the root of the .nupack or .nupkg files
//
// cf. https://learn.microsoft.com/en-us/nuget/reference/nuspec
type NuSpec struct {
	XMLName xml.Name `xml:"package"`
	Xmlns   string   `xml:"xmlns,attr,omitempty"`
	Meta    struct { // MetaData
		ID         string `xml:"id"`
		Version    string `xml:"version"`
		Title      string `xml:"title,omitempty"`
		Authors    string `xml:"authors"`
		Owners     string `xml:"owners,omitempty"`
		LicenseURL string `xml:"licenseUrl,omitempty"`
		License    struct {
			Text string `xml:",chardata"`
			Type string `xml:"type,attr"`
		} `xml:"license,omitempty"`
		ProjectURL       string `xml:"projectUrl,omitempty"`
		IconURL          string `xml:"iconUrl,omitempty"`
		ReqLicenseAccept bool   `xml:"requireLicenseAcceptance"`
		Description      string `xml:"description"`
		ReleaseNotes     string `xml:"releaseNotes,omitempty"`
		Copyright        string `xml:"copyright,omitempty"`
		Summary          string `xml:"summary,omitempty"`
		Language         string `xml:"language,omitempty"`
		Tags             string `xml:"tags,omitempty"`
		Dependencies     struct {
			Dependency []Dependency `xml:"dependency"`
		} `xml:"dependencies,omitempty"`
	} `xml:"metadata"`
	Files struct {
		File []File `xml:"file"`
	} `xml:"files,omitempty"`
}

// removeBOM removes any ByteOrderMark at the beginning of a given file content
func removeBOM(input []byte) []byte {
	if len(input) >= 2 {
		if input[0] == 254 && input[1] == 255 {
			// UTF-16 (BE)
			return input[2:]
		}
		if input[0] == 255 && input[1] == 254 {
			// UTF-16 (LE)
			return input[2:]
		}
		if len(input) >= 3 {
			if input[0] == 239 && input[1] == 187 && input[2] == 191 {
				// UTF-8
				return input[3:]
			}
			if len(input) >= 4 {
				if input[0] == 0 && input[1] == 0 && input[2] == 254 && input[3] == 255 {
					// UTF-32 (BE)
					return input[4:]
				}
				if input[0] == 255 && input[1] == 254 && input[2] == 0 && input[3] == 0 {
					// UTF-32 (LE)
					return input[4:]
				}
			}
		}
	}
	return input
}

// extractLicensesFromNuSpec tries to evaluate the license(s) from the .nuspec file struct and its containing archive (or NuGet package)
//
// cf. https://learn.microsoft.com/en-us/nuget/reference/nuspec#license
func (c *nugetLicenses) extractLicensesFromNuSpec(nuspec NuSpec, nugetArchive *zip.Reader) []pkg.License {
	out := []pkg.License{}

	switch nuspec.Meta.License.Type {
	case "expression":
		out = append(out, pkg.NewLicenseFromFields(nuspec.Meta.License.Text, nuspec.Meta.LicenseURL, nil))
	case "file":
		if licenseFile, err := nugetArchive.Open(nuspec.Meta.License.Text); err == nil {
			licenseFile.Close()
			if licenseFileData, err := io.ReadAll(licenseFile); err == nil {
				if foundLicenses, err := licenses.Parse(bytes.NewBuffer(removeBOM(licenseFileData)), file.NewLocation(nuspec.Meta.License.Text)); err == nil {
					out = append(out, foundLicenses...)
				}
			}
		}
	default:
		if nuspec.Meta.LicenseURL != "" { // Legacy: deprecated LicenseURL
			if response, err := httpClient.Get(nuspec.Meta.LicenseURL); err == nil && response.StatusCode == http.StatusOK {
				licenseFileData, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err == nil {
					if foundLicenses, err := licenses.Parse(bytes.NewBuffer(removeBOM(licenseFileData)), file.Location{}); err == nil {
						for _, foundLicense := range foundLicenses {
							foundLicense.URLs = append(foundLicense.URLs, nuspec.Meta.LicenseURL)
							out = append(out, foundLicense)
						}
					}
				}
			}
		} else { // Fallback: search for referenced license files
			for _, fileRef := range nuspec.Files.File {
				fileName := filepath.Base(fileRef.Source)
				if c.lowerLicenseFileNames.Has(strings.ToLower(fileName)) {
					if licenseFile, err := nugetArchive.Open(fileRef.Source); err == nil {
						defer licenseFile.Close()
						if licenseFileData, err := io.ReadAll(licenseFile); err == nil {
							if foundLicenses, err := licenses.Parse(bytes.NewBuffer(removeBOM(licenseFileData)), file.NewLocation(nuspec.Meta.License.Text)); err == nil {
								out = append(out, foundLicenses...)
							}
						}
					}
				}
			}
		}
	}

	return out
}

func (c *nugetLicenses) getLicensesFromRemotePackage(providerURL, moduleName, moduleVersion string) ([]pkg.License, bool) {
	out := []pkg.License{}
	foundPackage := false

	if response, err := httpClient.Get(fmt.Sprintf("%s/%s/%s", providerURL, moduleName, moduleVersion)); err == nil && response.StatusCode == http.StatusOK {
		foundPackage = true
		moduleData, err := io.ReadAll(response.Body)
		response.Body.Close()

		if err == nil {
			if zr, err := zip.NewReader(bytes.NewReader(moduleData), int64(len(moduleData))); err == nil {
				if specFile, err := zr.Open(moduleName + ".nuspec"); err == nil {
					defer specFile.Close()
					if specFileData, err := io.ReadAll(specFile); err == nil {
						var nuspec NuSpec

						if err = xml.Unmarshal(removeBOM(specFileData), &nuspec); err == nil {
							out = append(out, c.extractLicensesFromNuSpec(nuspec, zr)...)
						}
					}
				}
			}
		}
	}

	return out, foundPackage
}

func (c *nugetLicenses) findRemoteLicenses(moduleName, moduleVersion string) (out []pkg.License, err error) {
	if len(c.opts.Providers) == 0 {
		return nil, errors.ErrUnsupported
	}

	foundPackage := false
	for _, provider := range c.opts.Providers {
		out, foundPackage = c.getLicensesFromRemotePackage(provider, moduleName, moduleVersion)
		if foundPackage {
			break
		}
	}

	if foundPackage {
		return nil, errors.New("no license could be found")
	}
	return nil, errors.New("package could not be found")
}

func moduleDir(moduleName, moduleVersion string) string {
	return strings.ToLower(fmt.Sprintf("%s/%s", moduleName, moduleVersion))
}

func moduleSearchGlob(moduleName, moduleVersion string) string {
	return fmt.Sprintf("**/%s/*", moduleDir(moduleName, moduleVersion))
}

type nugetPackageFolders struct {
	PackageFolders map[string]any `json:"packageFolders"`
}

func getNuGetCachesFromProjectAssets(resolver file.Resolver) []string {
	paths := []string{}

	// Try to determine NuGet package folders from temporary object files
	if assetFiles, err := resolver.FilesByGlob("**/obj/project.assets.json"); err == nil && len(assetFiles) > 0 {
		for _, assetFile := range assetFiles {
			if contentReader, err := resolver.FileContentsByLocation(assetFile); err == nil {
				defer internal.CloseAndLogError(contentReader, assetFile.RealPath)

				if assetFileData, err := io.ReadAll(contentReader); err == nil {
					folders := nugetPackageFolders{}
					if err = json.Unmarshal(assetFileData, &folders); err == nil {
						for folder := range folders.PackageFolders {
							found := false
							for _, known := range paths {
								if known == folder {
									found = true
									break
								}
							}
							if !found {
								paths = append(paths, folder)
							}
						}
					}
				}
			}
		}
	}

	return paths
}

func getNuGetCachesFromSDK() []string {
	paths := []string{}

	// Query NuGet itself for its cache locations
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// cf. https://learn.microsoft.com/en-us/dotnet/core/tools/dotnet-nuget-locals
	cmd := exec.CommandContext(ctx, "dotnet", "nuget", "locals", "all", "-l", "--force-english-output")
	if stdout, err := cmd.StdoutPipe(); err == nil {
		if err := cmd.Start(); err == nil {
			if data, err := io.ReadAll(stdout); err == nil {
				lines := strings.Split(string(data), "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if lineParts := strings.Split(line, ": "); len(lineParts) == 2 {
						folder := lineParts[1]
						found := false
						for _, known := range paths {
							if known == folder {
								found = true
								break
							}
						}
						if !found {
							paths = append(paths, folder)
						}
					}
				}
			}
		}
	}

	return paths
}

func getLocalNugetFolderResolvers(resolver file.Resolver) []file.Resolver {
	nugetPackagePaths := []string{}
	if injectedCachePath := os.Getenv("TEST_PARSE_DOTNET_DEPS_INJECT_CACHE_LOCATION"); injectedCachePath != "" {
		nugetPackagePaths = append(nugetPackagePaths, injectedCachePath)
	} else {
		nugetPackagePaths = append(nugetPackagePaths, getNuGetCachesFromProjectAssets(resolver)...)

		nugetPackagePaths = append(nugetPackagePaths, getNuGetCachesFromSDK()...)
	}

	resolvers := []file.Resolver{}
	if len(nugetPackagePaths) > 0 {
		for _, nugetPackagePath := range nugetPackagePaths {
			resolvers = append(resolvers, fileresolver.NewFromUnindexedDirectory(nugetPackagePath))
		}
	}
	return resolvers
}
