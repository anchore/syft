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

// parseJavaManifest takes MANIFEST.MF file content and returns sections of parsed key/value pairs.
// For more information: https://docs.oracle.com/en/java/javase/11/docs/specs/jar/jar.html#jar-manifest
//
//nolint:funlen
func parseJavaManifest(path string, reader io.Reader) (*pkg.JavaManifest, error) {
	var manifest pkg.JavaManifest
	var sections []map[string]string

	currentSection := func() int {
		return len(sections) - 1
	}

	var lastKey string
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		line := scanner.Text()

		// empty lines denote section separators
		if line == "" {
			// we don't want to allocate a new section map that won't necessarily be used, do that once there is
			// a non-empty line to process

			// do not process line continuations after this
			lastKey = ""

			continue
		}

		if line[0] == ' ' {
			// this is a continuation

			if lastKey == "" {
				log.Debugf("java manifest %q: found continuation with no previous key: %q", path, line)
				continue
			}

			sections[currentSection()][lastKey] += strings.TrimSpace(line)

			continue
		}

		// this is a new key-value pair
		idx := strings.Index(line, ":")
		if idx == -1 {
			log.Debugf("java manifest %q: unable to split java manifest key-value pairs: %q", path, line)
			continue
		}

		key := strings.TrimSpace(line[0:idx])
		value := strings.TrimSpace(line[idx+1:])

		if key == "" {
			// don't attempt to add new keys or sections unless there is a non-empty key
			continue
		}

		if lastKey == "" {
			// we're entering a new section
			sections = append(sections, make(map[string]string))
		}

		sections[currentSection()][key] = value

		// keep track of key for potential future continuations
		lastKey = key
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
					// this should never happen. If it does, we want to know about it, but not necessarily stop
					// cataloging entirely... for this reason we only log.
					log.Debugf("java manifest section found without a name: %s", path)
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

func extractNameFromApacheMavenBundlePlugin(manifest *pkg.JavaManifest) string {
	// special case: from https://svn.apache.org/repos/asf/felix/releases/maven-bundle-plugin-1.2.0/doc/maven-bundle-plugin-bnd.html
	// "<Bundle-SymbolicName> is assumed to be "${groupId}.${artifactId}"."
	//
	// documentation from https://felix.apache.org/documentation/subprojects/apache-felix-maven-bundle-plugin-bnd.html
	// agrees this is the default behavior:
	//
	// - [1] if artifact.getFile is not null and the jar contains a OSGi Manifest with Bundle-SymbolicName property then that value is returned
	//
	// - [2] if groupId has only one section (no dots) and artifact.getFile is not null then the first package name with classes
	//   is returned. eg. commons-logging:commons-logging -> org.apache.commons.logging
	//
	// - [3] if artifactId is equal to last section of groupId then groupId is returned. eg. org.apache.maven:maven -> org.apache.maven
	//
	// - [4] if artifactId starts with last section of groupId that portion is removed. eg. org.apache.maven:maven-core -> org.apache.maven.core
	//   The computed symbolic name is also stored in the $(maven-symbolicname) property in case you want to add attributes or directives to it.
	//
	if manifest != nil {
		if strings.Contains(manifest.Main["Created-By"], "Apache Maven Bundle Plugin") {
			if symbolicName := manifest.Main["Bundle-SymbolicName"]; symbolicName != "" {
				// It is possible that `Bundle-SymbolicName` is just the groupID (like in the case of
				// https://repo1.maven.org/maven2/com/google/oauth-client/google-oauth-client/1.25.0/google-oauth-client-1.25.0.jar),
				// so if `Implementation-Vendor-Id` is equal to `Bundle-SymbolicName`, bail on this logic
				if vendorID := manifest.Main["Implementation-Vendor-Id"]; vendorID != "" && vendorID == symbolicName {
					return ""
				}

				// the problem with this approach is that we don't have a strong indication of the artifactId
				// not having a "." in it. However, by convention it is unlikely that an artifactId would have a ".".
				fields := strings.Split(symbolicName, ".")

				// grab the last field, this is the artifactId. Note: because of [3] we do not know if this value is
				// correct. That is, a group id of "commons-logging" may have caused BND to swap out the reference to
				// "org.apache.commons.logging", which means we'd interpret this as an artifact id of "logging",
				// which is not correct.
				// [correct]         https://mvnrepository.com/artifact/commons-logging/commons-logging
				// [still incorrect] https://mvnrepository.com/artifact/org.apache.commons.logging/org.apache.commons.logging
				return fields[len(fields)-1]
			}
		}
	}

	return ""
}

func extractNameFromArchiveFilename(a archiveFilename) string {
	if strings.Contains(a.name, ".") {
		// special case: this *might* be a group id + artifact id. By convention artifact ids do not have "." in them;
		// however, there are some specific exceptions like with the artifacts under
		// https://repo1.maven.org/maven2/org/eclipse/platform/
		if strings.HasPrefix(a.name, "org.eclipse.") {
			return a.name
		}

		fields := strings.Split(a.name, ".")
		return fields[len(fields)-1]
	}

	return a.name
}

func selectName(manifest *pkg.JavaManifest, filenameObj archiveFilename) string {
	name := extractNameFromApacheMavenBundlePlugin(manifest)
	if name != "" {
		return name
	}

	// the filename tends to be the next-best reference for the package name
	name = extractNameFromArchiveFilename(filenameObj)
	if name != "" {
		return name
	}

	// remaining fields in the manifest is a bit of a free-for-all depending on the build tooling used and package maintainer preferences
	if manifest != nil {
		switch {
		case manifest.Main["Name"] != "":
			// Manifest original spec...
			return manifest.Main["Name"]
		case manifest.Main["Bundle-Name"] != "":
			// BND tooling... TODO: this does not seem accurate (I don't see a reference in the BND tooling docs for this)
			return manifest.Main["Bundle-Name"]
		case manifest.Main["Short-Name"] != "":
			// Jenkins...
			return manifest.Main["Short-Name"]
		case manifest.Main["Extension-Name"] != "":
			// Jenkins...
			return manifest.Main["Extension-Name"]
		case manifest.Main["Implementation-Title"] != "":
			// last ditch effort...
			return manifest.Main["Implementation-Title"]
		}
	}
	return ""
}

func selectVersion(manifest *pkg.JavaManifest, filenameObj archiveFilename) string {
	if v := filenameObj.version; v != "" {
		return v
	}

	if manifest == nil {
		return ""
	}

	fieldNames := []string{
		"Implementation-Version",
		"Specification-Version",
		"Plugin-Version",
		"Bundle-Version",
	}

	for _, fieldName := range fieldNames {
		if v := fieldValueFromManifest(*manifest, fieldName); v != "" {
			return v
		}
	}

	return ""
}

func selectLicenses(manifest *pkg.JavaManifest) []string {
	result := []string{}
	if manifest == nil {
		return result
	}

	fieldNames := []string{
		"Bundle-License",
		"Plugin-License-Name",
	}

	for _, fieldName := range fieldNames {
		if v := fieldValueFromManifest(*manifest, fieldName); v != "" {
			result = append(result, v)
		}
	}

	return result
}

func fieldValueFromManifest(manifest pkg.JavaManifest, fieldName string) string {
	if value := manifest.Main[fieldName]; value != "" {
		return value
	}

	for _, section := range manifest.NamedSections {
		if value := section[fieldName]; value != "" {
			return value
		}
	}

	return ""
}
