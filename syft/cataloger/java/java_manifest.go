package java

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/mitchellh/mapstructure"
)

const manifestPath = "META-INF/MANIFEST.MF"

func parseJavaManifest(reader io.Reader) (*pkg.JavaManifest, error) {
	var manifest pkg.JavaManifest
	manifestMap := make(map[string]string)
	scanner := bufio.NewScanner(reader)
	var lastKey string
	for scanner.Scan() {
		line := scanner.Text()

		// ignore empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		if line[0] == ' ' {
			// this is a continuation
			if lastKey == "" {
				return nil, fmt.Errorf("found continuation with no previous key (%s)", line)
			}
			manifestMap[lastKey] += strings.TrimSpace(line)
		} else {
			// this is a new key-value pair
			idx := strings.Index(line, ":")
			if idx == -1 {
				return nil, fmt.Errorf("unable to split java manifest key-value pairs: %q", line)
			}

			key := strings.TrimSpace(line[0:idx])
			value := strings.TrimSpace(line[idx+1:])
			manifestMap[key] = value

			// keep track of key for future continuations
			lastKey = key
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to read java manifest: %w", err)
	}

	if err := mapstructure.Decode(manifestMap, &manifest); err != nil {
		return nil, fmt.Errorf("unable to parse java manifest: %w", err)
	}

	// clean select fields
	if strings.Trim(manifest.ImplVersion, " ") != "" {
		// transform versions with dates attached to just versions (e.g. "1.3 2244 October 5 2008" --> "1.3")
		manifest.ImplVersion = strings.Split(manifest.ImplVersion, " ")[0]
	}

	return &manifest, nil
}

func selectName(manifest *pkg.JavaManifest, filenameObj archiveFilename) string {
	var name string
	switch {
	case filenameObj.name() != "":
		name = filenameObj.name()
	case manifest.Name != "":
		// Manifest original spec...
		name = manifest.Name
	case manifest.Extra["Bundle-Name"] != "":
		// BND tooling...
		name = manifest.Extra["Bundle-Name"]
	case manifest.Extra["Short-Name"] != "":
		// Jenkins...
		name = manifest.Extra["Short-Name"]
	case manifest.Extra["Extension-Name"] != "":
		// Jenkins...
		name = manifest.Extra["Extension-Name"]
	}
	return name
}

func selectVersion(manifest *pkg.JavaManifest, filenameObj archiveFilename) string {
	var version string
	switch {
	case manifest.ImplVersion != "":
		version = manifest.ImplVersion
	case filenameObj.version() != "":
		version = filenameObj.version()
	case manifest.SpecVersion != "":
		version = manifest.SpecVersion
	case manifest.Extra["Plugin-Version"] != "":
		version = manifest.Extra["Plugin-Version"]
	}
	return version
}
