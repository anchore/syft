package java

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/imgbom/internal/file"

	"github.com/anchore/imgbom/imgbom/pkg"
	"github.com/mitchellh/mapstructure"
)

const manifestPath = "META-INF/MANIFEST.MF"

func parseJavaManifest(reader io.Reader) (*pkg.JavaManifest, error) {
	var manifest pkg.JavaManifest
	manifestMap := make(map[string]string)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		// ignore empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		idx := strings.Index(line, ":")
		if idx == -1 {
			return nil, fmt.Errorf("unable to split java manifest key-value pairs: %q", line)
		}

		key := strings.TrimSpace(line[0:idx])
		value := strings.TrimSpace(line[idx+1:])
		manifestMap[key] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable read java manifest: %w", err)
	}

	if err := mapstructure.Decode(manifestMap, &manifest); err != nil {
		return nil, fmt.Errorf("unable parse java manifest: %w", err)
	}

	return &manifest, nil
}

func newPackageFromJavaManifest(virtualPath, archivePath string, fileManifest file.ZipManifest) (*pkg.Package, error) {
	// search and parse java manifest files
	manifestMatches := fileManifest.GlobMatch(manifestPath)
	if len(manifestMatches) > 1 {
		return nil, fmt.Errorf("found multiple manifests in the jar: %+v", manifestMatches)
	} else if len(manifestMatches) == 0 {
		// we did not find any manifests, but that may not be a problem (there may be other information to generate packages for)
		return nil, nil
	}

	// fetch the manifest file
	contents, err := file.ExtractFilesFromZip(archivePath, manifestMatches...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract java manifests: %w", err)
	}

	// parse the manifest file into a rich object
	manifestContents := contents[manifestMatches[0]]
	manifest, err := parseJavaManifest(strings.NewReader(manifestContents))
	if err != nil {
		return nil, fmt.Errorf("failed to parse java manifest (%s): %w", virtualPath, err)
	}

	filenameObj := newJavaArchiveFilename(virtualPath)

	var name string
	switch {
	case manifest.Name != "":
		name = manifest.Name
	case filenameObj.name() != "":
		name = filenameObj.name()
	}

	var version string
	switch {
	case manifest.ImplVersion != "":
		version = manifest.ImplVersion
	case filenameObj.version() != "":
		version = filenameObj.version()
	case manifest.SpecVersion != "":
		version = manifest.SpecVersion
	}

	return &pkg.Package{
		Name:     name,
		Version:  version,
		Language: pkg.Java,
		Metadata: pkg.JavaMetadata{
			Manifest: manifest,
		},
	}, nil
}
