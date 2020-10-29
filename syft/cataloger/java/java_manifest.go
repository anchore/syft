package java

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/syft/pkg"
	"github.com/mitchellh/mapstructure"
)

const manifestGlob = "/META-INF/MANIFEST.MF"

// nolint:funlen
func parseJavaManifest(reader io.Reader) (*pkg.JavaManifest, error) {
	var manifest pkg.JavaManifest
	sections := []map[string]string{
		make(map[string]string),
	}
	currentSection := 0
	scanner := bufio.NewScanner(reader)
	var lastKey string
	for scanner.Scan() {
		line := scanner.Text()

		// empty lines denote section separators
		if strings.TrimSpace(line) == "" {
			currentSection++
			// we don't want to allocate a new section map that wont necessarily be used, do that once there is
			// a non-empty line to process

			// do not process line continuations after this
			lastKey = ""
			continue
		} else if currentSection >= len(sections) {
			sections = append(sections, make(map[string]string))
		}

		if line[0] == ' ' {
			// this is a continuation
			if lastKey == "" {
				return nil, fmt.Errorf("found continuation with no previous key (%s)", line)
			}
			sections[currentSection][lastKey] += strings.TrimSpace(line)
		} else {
			// this is a new key-value pair
			idx := strings.Index(line, ":")
			if idx == -1 {
				return nil, fmt.Errorf("unable to split java manifest key-value pairs: %q", line)
			}

			key := strings.TrimSpace(line[0:idx])
			value := strings.TrimSpace(line[idx+1:])
			sections[currentSection][key] = value

			// keep track of key for potential future continuations
			lastKey = key
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to read java manifest: %w", err)
	}

	if err := mapstructure.Decode(sections[0], &manifest); err != nil {
		return nil, fmt.Errorf("unable to parse java manifest: %w", err)
	}

	// append on extra sections
	if len(sections) > 1 {
		manifest.Sections = sections[1:]
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

	// in situations where we hit this point and no name was
	// determined, look at the Implementation-Title
	if name == "" && manifest.ImplTitle != "" {
		name = manifest.ImplTitle
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
