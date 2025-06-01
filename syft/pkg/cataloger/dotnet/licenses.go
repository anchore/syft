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
	"io/fs"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/internal/fileresolver"
	"github.com/anchore/syft/syft/pkg"
	"github.com/scylladb/go-set/strset"
)

var (
	httpClient = &http.Client{
		Timeout: time.Second * 5,
	}

	defaultProvidersMutex sync.Mutex
	defaultProviders      = ""
)

type nugetLicenseResolver struct {
	opts                     CatalogerConfig
	localNuGetCacheResolvers []file.Resolver
	lowerLicenseFileNames    *strset.Set
	assetDefinitions         []projectAssets
}

func newNugetLicenseResolver(config CatalogerConfig) nugetLicenseResolver {
	return nugetLicenseResolver{
		opts:                     config,
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

func (c *nugetLicenseResolver) getLicenses(ctx context.Context, moduleName, moduleVersion string) ([]pkg.License, error) {
	var licenses []pkg.License

	if c.opts.SearchLocalLicenses {
		if c.localNuGetCacheResolvers == nil {
			// Try to determine NuGet package folder resolvers
			c.localNuGetCacheResolvers = c.getLocalNugetFolderResolvers(c.assetDefinitions)
		}

		// if we're running against a directory on the filesystem, it may not include the
		// user's homedir, so we defer to using the localModCacheResolvers
		for _, resolver := range c.localNuGetCacheResolvers {
			if lics, err := c.findLocalLicenses(ctx, resolver, moduleSearchGlob(moduleName, moduleVersion)); err == nil {
				licenses = appendNewLicenses(licenses, lics...)
				return licenses, nil
			}
		}
	}

	if c.opts.SearchRemoteLicenses {
		if lics, err := c.findRemoteLicenses(ctx, moduleName, moduleVersion, c.assetDefinitions...); err == nil {
			licenses = appendNewLicenses(licenses, lics...)
		}
	}

	if len(licenses) == 0 {
		return licenses, errors.New("no licenses found")
	}
	return licenses, nil
}

func (c *nugetLicenseResolver) findLocalLicenses(ctx context.Context, resolver file.Resolver, globMatch string) ([]pkg.License, error) {
	if resolver == nil {
		return nil, nil
	}

	locations, err := resolver.FilesByGlob(globMatch)
	if err != nil {
		return nil, err
	}

	var out []pkg.License
	for _, l := range locations {
		fileName := filepath.Base(l.RealPath)
		if c.lowerLicenseFileNames.Has(strings.ToLower(fileName)) {
			parsed, err := extractLicensesFromResolvedFile(ctx, resolver, l)

			if err != nil {
				continue
			}

			out = append(out, parsed...)
		}
	}

	return out, err
}

func extractLicensesFromResolvedFile(ctx context.Context, resolver file.Resolver, l file.Location) (out []pkg.License, err error) {
	contents, err := resolver.FileContentsByLocation(l)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contents, l.RealPath)

	out = pkg.NewLicensesFromReadCloserWithContext(ctx, file.NewLocationReadCloser(l, contents))

	return out, nil
}

// nuspecFile is used in the NuSpec struct
type nuspecFile struct {
	Source string `xml:"src,attr"`
	Target string `xml:"target,attr"`
}

// nuspecDependency is used in the NuSpec struct
type nuspecDependency struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

type nuspecLicense struct {
	Text string `xml:",chardata"`
	Type string `xml:"type,attr"`
}
type nuspecDependencies struct {
	Dependency []nuspecDependency `xml:"dependency"`
}

type nuspecMetaData struct { // MetaData
	ID               string             `xml:"id"`
	Version          string             `xml:"version"`
	Title            string             `xml:"title,omitempty"`
	Authors          string             `xml:"authors"`
	Owners           string             `xml:"owners,omitempty"`
	LicenseURL       string             `xml:"licenseUrl,omitempty"`
	License          nuspecLicense      `xml:"license,omitempty"`
	ProjectURL       string             `xml:"projectUrl,omitempty"`
	IconURL          string             `xml:"iconUrl,omitempty"`
	ReqLicenseAccept bool               `xml:"requireLicenseAcceptance"`
	Description      string             `xml:"description"`
	ReleaseNotes     string             `xml:"releaseNotes,omitempty"`
	Copyright        string             `xml:"copyright,omitempty"`
	Summary          string             `xml:"summary,omitempty"`
	Language         string             `xml:"language,omitempty"`
	Tags             string             `xml:"tags,omitempty"`
	Dependencies     nuspecDependencies `xml:"dependencies,omitempty"`
}

type nuspecFiles struct {
	File []nuspecFile `xml:"file"`
}

// nugetSpecification represents a .nuspec XML file found in the root of the .nupack or .nupkg files
//
// cf. https://learn.microsoft.com/en-us/nuget/reference/nuspec
type nugetSpecification struct {
	XMLName xml.Name       `xml:"package"`
	Xmlns   string         `xml:"xmlns,attr,omitempty"`
	Meta    nuspecMetaData `xml:"metadata"`
	Files   nuspecFiles    `xml:"files,omitempty"`
}

// removeBOM removes any ByteOrderMark at the beginning of a given file content
func removeBOM(input []byte) []byte {
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
	if len(input) >= 3 {
		if input[0] == 239 && input[1] == 187 && input[2] == 191 {
			// UTF-8
			return input[3:]
		}
	}
	if len(input) >= 2 {
		if input[0] == 254 && input[1] == 255 {
			// UTF-16 (BE)
			return input[2:]
		}
		if input[0] == 255 && input[1] == 254 {
			// UTF-16 (LE)
			return input[2:]
		}
	}
	return input
}

type bytesReadCloser struct {
	bytes.Buffer
}

func (brc *bytesReadCloser) Close() error {
	return nil
}

func newBytesReadCloser(data []byte) *bytesReadCloser {
	return &bytesReadCloser{
		Buffer: *bytes.NewBuffer(data),
	}
}

func extractLicensesFromNuGetContentFile(ctx context.Context, filePath string, nugetArchive *zip.Reader) []pkg.License {
	out := []pkg.License{}

	if nugetArchive != nil {
		if licenseFile, err := nugetArchive.Open(filePath); err == nil {
			defer internal.CloseAndLogError(licenseFile, filePath)
			licenseFileData, err := io.ReadAll(licenseFile)

			if err == nil {
				foundLicenses := pkg.NewLicensesFromReadCloserWithContext(ctx, file.NewLocationReadCloser(file.NewLocation(filePath), newBytesReadCloser(removeBOM(licenseFileData))))

				out = append(out, foundLicenses...)
			}
		}
	}

	return out
}

func extractLicensesFromURLReference(ctx context.Context, url string) []pkg.License {
	out := []pkg.License{}

	if response, err := httpClient.Get(url); err == nil && response.StatusCode == http.StatusOK {
		licenseFileData, err := io.ReadAll(response.Body)
		response.Body.Close()

		if err == nil {
			foundLicenses := pkg.NewLicensesFromReadCloserWithContext(ctx, file.NewLocationReadCloser(file.NewLocation(url), newBytesReadCloser(removeBOM(licenseFileData))))

			for _, foundLicense := range foundLicenses {
				foundLicense.URLs = append(foundLicense.URLs, url)
				out = append(out, foundLicense)
			}
		}
	}

	return out
}

// extractLicensesFromNuSpec tries to evaluate the license(s) from the .nuspec file struct and its containing archive (or NuGet package)
//
// cf. https://learn.microsoft.com/en-us/nuget/reference/nuspec#license
func (c *nugetLicenseResolver) extractLicensesFromNuSpec(ctx context.Context, nuspec nugetSpecification, nugetArchive *zip.Reader) []pkg.License {
	out := []pkg.License{}

	switch nuspec.Meta.License.Type {
	case "expression":
		out = append(out, pkg.NewLicenseFromFields(nuspec.Meta.License.Text, nuspec.Meta.LicenseURL, nil))
	case "file":
		out = append(out, extractLicensesFromNuGetContentFile(ctx, nuspec.Meta.License.Text, nugetArchive)...)
	default:
		if nuspec.Meta.LicenseURL != "" { // Legacy: deprecated LicenseURL
			out = append(out, extractLicensesFromURLReference(ctx, nuspec.Meta.LicenseURL)...)
		} else { // Fallback: search for referenced license files
			for _, fileRef := range nuspec.Files.File {
				fileName := filepath.Base(fileRef.Source)
				if c.lowerLicenseFileNames.Has(strings.ToLower(fileName)) {
					out = append(out, extractLicensesFromNuGetContentFile(ctx, fileRef.Source, nugetArchive)...)
				}
			}
		}
	}

	return out
}

type zipDir interface {
	ReadDir(count int) ([]fs.DirEntry, error)
}

func (c *nugetLicenseResolver) extractLicensesFromArchive(ctx context.Context, entries []fs.DirEntry, zr *zip.Reader) []pkg.License {
	out := []pkg.License{}

	for _, entry := range entries {
		if strings.HasSuffix(strings.ToLower(entry.Name()), ".nuspec") {
			if specFile, err := zr.Open(entry.Name()); err == nil {
				specFileData, err := io.ReadAll(specFile)
				specFile.Close()
				if err == nil {
					var nuspec nugetSpecification

					if err = xml.Unmarshal(removeBOM(specFileData), &nuspec); err == nil {
						out = append(out, c.extractLicensesFromNuSpec(ctx, nuspec, zr)...)
					}
				}
			}
			break
		}
	}

	return out
}

func (c *nugetLicenseResolver) extractLicensesFromBinaryNuGetPackage(ctx context.Context, binary []byte) []pkg.License {
	out := []pkg.License{}

	if zr, err := zip.NewReader(bytes.NewReader(binary), int64(len(binary))); err == nil {
		if _nugetContents, err := zr.Open("."); err == nil {
			if nugetContents, ok := _nugetContents.(zipDir); ok {
				if entries, err := nugetContents.ReadDir(0); err == nil {
					out = append(out, c.extractLicensesFromArchive(ctx, entries, zr)...)
				}
			}
		}
	}

	return out
}

func (c *nugetLicenseResolver) getResponseForRemotePackage(providerURL, moduleName, moduleVersion string) (*http.Response, error) {
	var response *http.Response
	var err error

	url := fmt.Sprintf("%s/%s/%s/%s.%s.nupkg", strings.TrimSuffix(providerURL, "/"), moduleName, moduleVersion, moduleName, moduleVersion)
	response, err = httpClient.Get(url)
	if err == nil {
		if response.StatusCode == http.StatusUnauthorized && len(c.opts.ProviderCredentials) > 0 {
			if response.Body != nil {
				response.Body.Close()
			}
			// Let's try, using the given credentials
			for _, credential := range c.opts.ProviderCredentials {
				req, _ := http.NewRequest("GET", url, nil)
				req.SetBasicAuth(credential.Username, credential.Password)
				response, err = httpClient.Do(req)
				if err != nil {
					break
				}
				if response.StatusCode == http.StatusOK {
					break
				}
				if response.Body != nil {
					response.Body.Close()
				}
			}
		}
	}

	return response, err
}

func (c *nugetLicenseResolver) getLicensesFromRemotePackage(ctx context.Context, providerURL, moduleName, moduleVersion string) ([]pkg.License, bool) {
	out := []pkg.License{}
	foundPackage := false

	response, err := c.getResponseForRemotePackage(providerURL, moduleName, moduleVersion)
	if err == nil && response.StatusCode == http.StatusOK {
		foundPackage = true
		moduleData, err := io.ReadAll(response.Body)
		response.Body.Close()

		if err == nil {
			out = c.extractLicensesFromBinaryNuGetPackage(ctx, moduleData)
		}
	}

	return out, foundPackage
}

func findMatchingLibrariesInProjectAssets(moduleName, moduleVersion string, assets []projectAssets) (projectLibrary, error) {
	errNotFound := fmt.Errorf("no library match was found")
	if len(assets) == 0 {
		return projectLibrary{}, errNotFound
	}

	expectedName := fmt.Sprintf("%s/%s", strings.TrimSuffix(strings.TrimSuffix(strings.ToLower(moduleName), ".dll"), ".exe"), moduleVersion)
	for _, asset := range assets {
		for name, library := range asset.Libraries {
			if strings.HasPrefix(strings.ToLower(expectedName), strings.ToLower(name)) {
				return library, nil
			}
		}
	}

	return projectLibrary{}, errNotFound
}

func (c *nugetLicenseResolver) findRemoteLicenses(ctx context.Context, moduleName, moduleVersion string, assets ...projectAssets) (out []pkg.License, err error) {
	if len(c.opts.Providers) == 0 {
		return nil, errors.ErrUnsupported
	}

	if matchingLibrary, err := findMatchingLibrariesInProjectAssets(moduleName, moduleVersion, assets); err == nil {
		// Search for matched library rather than using a
		if pathParts := strings.Split(matchingLibrary.Path, "/"); len(pathParts) == 2 {
			moduleName = pathParts[0]
			moduleVersion = pathParts[1]
		}
	}

	foundPackage := false
	for _, provider := range c.opts.Providers {
		out, foundPackage = c.getLicensesFromRemotePackage(ctx, provider, moduleName, moduleVersion)
		if foundPackage {
			break
		}
	}

	if len(out) > 0 {
		return out, nil
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

type projectLibrary struct {
	SHA256 string   `json:"sha256"`
	Type   string   `json:"type"`
	Path   string   `json:"path"`
	Files  []string `json:"files"`
}

type projectAssets struct {
	Libraries      map[string]projectLibrary `json:"libraries"`
	PackageFolders map[string]any            `json:"packageFolders"`
}

func getProjectAssets(resolver file.Resolver) ([]projectAssets, error) {
	assets := []projectAssets{}
	var err error

	// Try to determine NuGet package assets from temporary object files
	// (usually located in the /obj folder)
	var assetFiles []file.Location
	if assetFiles, err = resolver.FilesByGlob("**/project.assets.json"); err == nil && len(assetFiles) > 0 {
		for _, assetFile := range assetFiles {
			assetDefinition, err := extractProjectAssetsFromResolvedFile(resolver, assetFile)
			if err != nil {
				continue
			}

			assets = append(assets, *assetDefinition)
		}

		if len(assets) == 0 {
			err = fmt.Errorf("could not retrieve any asset definitions")
		}
	}

	return assets, err
}

func extractProjectAssetsFromResolvedFile(resolver file.Resolver, l file.Location) (asset *projectAssets, err error) {
	contentReader, err := resolver.FileContentsByLocation(l)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(contentReader, l.RealPath)

	assetFileData, err := io.ReadAll(contentReader)
	if err != nil {
		return nil, err
	}

	asset = &projectAssets{}
	if err = json.Unmarshal(assetFileData, asset); err != nil {
		return nil, err
	}

	return asset, nil
}

func getNuGetCachesFromProjectAssets(assets []projectAssets) []string {
	paths := []string{}

	// Try to determine NuGet package folders from project assets
	for _, assetDefinition := range assets {
		for folder := range assetDefinition.PackageFolders {
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

	return paths
}

func parseSDKLocalCachePathsOutput(outputLines []string) []string {
	paths := []string{}

	for _, line := range outputLines {
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

	return paths
}

func (c *nugetLicenseResolver) getLocalNugetFolderResolvers(assetDefinitions []projectAssets) []file.Resolver {
	nugetPackagePaths := []string{}
	if len(c.opts.LocalCachePaths) > 0 {
		nugetPackagePaths = append(nugetPackagePaths, c.opts.LocalCachePaths...)
	} else {
		nugetPackagePaths = append(nugetPackagePaths, getNuGetCachesFromProjectAssets(assetDefinitions)...)
	}

	resolvers := []file.Resolver{}
	for _, nugetPackagePath := range nugetPackagePaths {
		resolvers = append(resolvers, fileresolver.NewFromUnindexedDirectory(nugetPackagePath))
	}
	return resolvers
}
