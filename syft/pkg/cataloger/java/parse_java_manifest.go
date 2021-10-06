package java

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

const manifestGlob = "/META-INF/MANIFEST.MF"

// nolint:funlen
// parseJavaManifest takes MANIFEST.MF file content and returns sections of parsed key/value pairs.
// For more information: https://docs.oracle.com/en/java/javase/11/docs/specs/jar/jar.html#jar-manifest
func parseJavaManifest(path string, reader io.Reader) (*pkg.JavaManifest, error) {
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

	if len(sections) > 0 {
		manifest.Main = sections[0]
		if len(sections) > 1 {
			manifest.NamedSections = make(map[string]map[string]string)
			for i, s := range sections[1:] {
				name, ok := s["Name"]
				if !ok {
					// per the manifest spec (https://docs.oracle.com/en/java/javase/11/docs/specs/jar/jar.html#jar-manifest)
					// this should never happen. If it does we want to know about it, but not necessarily stop
					// cataloging entirely... for this reason we only log.
					log.Warnf("java manifest section found without a name: %s", path)
					name = strconv.Itoa(i)
				} else {
					delete(s, "Name")
				}
				manifest.NamedSections[name] = s
			}
		}
	}

	return &manifest, nil
}

func selectName(manifest *pkg.JavaManifest, filenameObj archiveFilename) string {
	var name string
	switch {
	case filenameObj.name != "":
		name = filenameObj.name
	case manifest.Main["Name"] != "":
		// Manifest original spec...
		name = manifest.Main["Name"]
	case manifest.Main["Bundle-Name"] != "":
		// BND tooling...
		name = manifest.Main["Bundle-Name"]
	case manifest.Main["Short-Name"] != "":
		// Jenkins...
		name = manifest.Main["Short-Name"]
	case manifest.Main["Extension-Name"] != "":
		// Jenkins...
		name = manifest.Main["Extension-Name"]
	case manifest.Main["Implementation-Title"] != "":
		// last ditch effort...
		name = manifest.Main["Implementation-Title"]
	}
	return name
}

func selectVersion(manifest *pkg.JavaManifest, filenameObj archiveFilename) string {
	var version string
	switch {
	case filenameObj.version != "":
		version = filenameObj.version
	case manifest.Main["Implementation-Version"] != "":
		version = manifest.Main["Implementation-Version"]
	case manifest.Main["Specification-Version"] != "":
		version = manifest.Main["Specification-Version"]
	case manifest.Main["Plugin-Version"] != "":
		version = manifest.Main["Plugin-Version"]
	}
	return version
}
