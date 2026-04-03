package electron

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var (
	_ generic.Parser = parseAsarArchive
	_ generic.Parser = parsePackageJSON
)

func parsePackageJSON(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	defer internal.CloseAndLogError(reader, reader.Path())

	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("read package.json: %w", err)
	}

	p, err := parsePackageJSONFromContents(contents, reader.Location)
	if err != nil {
		return nil, nil, err
	}

	if p.Name == "" || p.Version == "" {
		return nil, nil, nil
	}

	return []pkg.Package{p}, nil, nil
}

type asarHeader struct {
	Files map[string]asarEntry `json:"files"`
}

type asarEntry struct {
	Files  map[string]asarEntry `json:"files,omitempty"`
	Size   int64                `json:"size,omitempty"`
	Offset string               `json:"offset,omitempty"`
}

func parseAsarArchive(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	defer internal.CloseAndLogError(reader, reader.Path())

	asarData, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("read ASAR: %w", err)
	}

	header, headerSize, err := parseAsarHeader(asarData)
	if err != nil {
		return nil, nil, fmt.Errorf("parse ASAR header: %w", err)
	}

	packageJSONPaths := findPackageJSONFilesFromHeader(header)
	if len(packageJSONPaths) == 0 {
		log.Debugf("no package.json in ASAR: %s", reader.Path())
		return nil, nil, nil
	}

	var pkgs []pkg.Package

	for _, pkgPath := range packageJSONPaths {
		entry, found := findEntry(header, pkgPath)
		if !found {
			log.Debugf("entry not found: %s", pkgPath)
			continue
		}

		contents, err := readAsarFile(asarData, headerSize, entry)
		if err != nil {
			log.Debugf("read pkg %s: %v", pkgPath, err)
			continue
		}

		virtualPath := fmt.Sprintf("%s:%s", reader.Path(), pkgPath)
		virtualLocation := file.NewVirtualLocationFromCoordinates(
			reader.Coordinates,
			virtualPath,
		)

		npmPkg, err := parsePackageJSONFromContents(contents, virtualLocation)
		if err != nil {
			log.Debugf("parse pkg %s: %v", pkgPath, err)
			continue
		}

		if npmPkg.Name == "" || npmPkg.Version == "" {
			continue
		}

		pkgs = append(pkgs, npmPkg)
	}

	log.Debugf("%d pkgs in ASAR: %s", len(pkgs), reader.Path())

	return pkgs, nil, nil
}

// parseAsarHeader decodes ASAR Chromium pickle format:
// [4B pickle hdr][4B hdr size w/ pad][4B hdr size][4B json size][json][pad][files]
func parseAsarHeader(data []byte) (*asarHeader, int64, error) {
	if len(data) < 16 {
		return nil, 0, errors.New("ASAR file too small")
	}

	pickleSize := binary.LittleEndian.Uint32(data[0:4])
	if pickleSize != 4 {
		return nil, 0, fmt.Errorf("bad pickle hdr size: %d", pickleSize)
	}

	headerSize1 := binary.LittleEndian.Uint32(data[4:8])
	jsonSize := binary.LittleEndian.Uint32(data[12:16])

	jsonStart := int64(16)
	jsonEnd := jsonStart + int64(jsonSize)

	if int64(len(data)) < jsonEnd {
		return nil, 0, fmt.Errorf("ASAR truncated: need %d bytes", jsonEnd)
	}

	var header asarHeader
	if err := json.Unmarshal(data[jsonStart:jsonEnd], &header); err != nil {
		return nil, 0, fmt.Errorf("unmarshal ASAR header: %w", err)
	}

	contentStart := int64(8) + int64(headerSize1)

	return &header, contentStart, nil
}

func findEntry(header *asarHeader, entryPath string) (*asarEntry, bool) {
	parts := strings.Split(entryPath, "/")

	current := header.Files
	for i, part := range parts {
		entry, ok := current[part]
		if !ok {
			return nil, false
		}

		if i == len(parts)-1 {
			return &entry, true
		}

		current = entry.Files
	}

	return nil, false
}

func readAsarFile(data []byte, headerSize int64, entry *asarEntry) ([]byte, error) {
	var offset int64
	if entry.Offset != "" {
		var err error
		offset, err = strconv.ParseInt(entry.Offset, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse offset: %w", err)
		}
	}

	start := headerSize + offset
	end := start + entry.Size

	if end > int64(len(data)) {
		return nil, errors.New("file extends beyond ASAR bounds")
	}

	return data[start:end], nil
}

func findPackageJSONFilesFromHeader(header *asarHeader) []string {
	var paths []string
	walkHeader(header.Files, "", func(entryPath string) {
		if filepath.Base(entryPath) != "package.json" {
			return
		}

		if entryPath == "package.json" {
			paths = append(paths, entryPath)
			return
		}

		dir := path.Dir(entryPath)

		if strings.Contains(entryPath, "node_modules/") {
			if path.Base(dir) == "node_modules" {
				return
			}
			paths = append(paths, entryPath)
			return
		}

		// root-level pkgs in node_modules.asar
		if !strings.Contains(dir, "/") && dir != "" {
			paths = append(paths, entryPath)
			return
		}

		// nested pkgs under top-level
		if dir != "" && !strings.HasPrefix(entryPath, ".") {
			paths = append(paths, entryPath)
		}
	})

	return paths
}

func walkHeader(files map[string]asarEntry, currentPath string, fn func(path string)) {
	for name, entry := range files {
		entryPath := name
		if currentPath != "" {
			entryPath = path.Join(currentPath, name)
		}

		if entry.Files != nil {
			walkHeader(entry.Files, entryPath, fn)
		} else {
			fn(entryPath)
		}
	}
}

type packageJSONForParsing struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
	Author      any    `json:"author"`
	Homepage    string `json:"homepage"`
	License     any    `json:"license"`
	Repository  any    `json:"repository"`
	Private     bool   `json:"private"`
}

func parsePackageJSONFromContents(contents []byte, location file.Location) (pkg.Package, error) {
	contents = bytes.TrimPrefix(contents, []byte{0xef, 0xbb, 0xbf})

	var pkgJSON packageJSONForParsing
	if err := json.Unmarshal(contents, &pkgJSON); err != nil {
		return pkg.Package{}, fmt.Errorf("unmarshal package.json: %w", err)
	}

	author := extractAuthor(pkgJSON.Author)

	license := extractLicense(pkgJSON.License)

	repoURL := extractRepositoryURL(pkgJSON.Repository)

	var licenses pkg.LicenseSet
	if license != "" {
		licenses = pkg.NewLicenseSet(pkg.NewLicenseFromLocations(license, location))
	}

	p := pkg.Package{
		Name:      pkgJSON.Name,
		Version:   pkgJSON.Version,
		PURL:      packageURL(pkgJSON.Name, pkgJSON.Version),
		Locations: file.NewLocationSet(location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Language:  pkg.JavaScript,
		Licenses:  licenses,
		Type:      pkg.NpmPkg,
		Metadata: pkg.NpmPackage{
			Name:        pkgJSON.Name,
			Version:     pkgJSON.Version,
			Description: pkgJSON.Description,
			Author:      author,
			Homepage:    pkgJSON.Homepage,
			URL:         repoURL,
			Private:     pkgJSON.Private,
		},
	}

	p.SetID()

	return p, nil
}

func extractAuthor(author any) string {
	if author == nil {
		return ""
	}

	switch v := author.(type) {
	case string:
		return v
	case map[string]any:
		var parts []string
		if name, ok := v["name"].(string); ok && name != "" {
			parts = append(parts, name)
		}
		if email, ok := v["email"].(string); ok && email != "" {
			parts = append(parts, fmt.Sprintf("<%s>", email))
		}
		if url, ok := v["url"].(string); ok && url != "" {
			parts = append(parts, fmt.Sprintf("(%s)", url))
		}
		return strings.Join(parts, " ")
	default:
		return ""
	}
}

func extractLicense(license any) string {
	if license == nil {
		return ""
	}

	switch v := license.(type) {
	case string:
		return v
	case map[string]any:
		if licType, ok := v["type"].(string); ok {
			return licType
		}
	}
	return ""
}

func extractRepositoryURL(repo any) string {
	if repo == nil {
		return ""
	}

	switch v := repo.(type) {
	case string:
		return v
	case map[string]any:
		if url, ok := v["url"].(string); ok {
			return url
		}
	}
	return ""
}

func packageURL(name, version string) string {
	var namespace string

	fields := strings.SplitN(name, "/", 2)
	if len(fields) > 1 {
		namespace = fields[0]
		name = fields[1]
	}

	return packageurl.NewPackageURL(
		packageurl.TypeNPM,
		namespace,
		name,
		version,
		nil,
		"",
	).ToString()
}
