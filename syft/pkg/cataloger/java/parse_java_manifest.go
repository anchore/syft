package java

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"

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
	sections := make([]pkg.KeyValues, 0)

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

			lastSection := sections[currentSection()]

			sections[currentSection()][len(lastSection)-1].Value += strings.TrimSpace(line)

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
			sections = append(sections, make(pkg.KeyValues, 0))
		}

		sections[currentSection()] = append(sections[currentSection()], pkg.KeyValue{
			Key:   key,
			Value: value,
		})

		// keep track of key for potential future continuations
		lastKey = key
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("unable to read java manifest: %w", err)
	}

	if len(sections) > 0 {
		manifest.Main = sections[0]
		if len(sections) > 1 {
			manifest.Sections = sections[1:]
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
		if strings.Contains(manifest.Main.MustGet("Created-By"), "Apache Maven Bundle Plugin") {
			if symbolicName := manifest.Main.MustGet("Bundle-SymbolicName"); symbolicName != "" {
				// It is possible that `Bundle-SymbolicName` is just the groupID (like in the case of
				// https://repo1.maven.org/maven2/com/google/oauth-client/google-oauth-client/1.25.0/google-oauth-client-1.25.0.jar),
				// so if `Implementation-Vendor-Id` is equal to `Bundle-SymbolicName`, bail on this logic
				if vendorID := manifest.Main.MustGet("Implementation-Vendor-Id"); vendorID != "" && vendorID == symbolicName {
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

		// Maybe the filename is like groupid + . + artifactid. If so, return artifact id.
		fields := strings.Split(a.name, ".")
		maybeGroupID := true
		for _, f := range fields {
			if !isValidJavaIdentifier(f) {
				maybeGroupID = false
				break
			}
		}
		if maybeGroupID {
			return fields[len(fields)-1]
		}
	}

	return a.name
}

func isValidJavaIdentifier(field string) bool {
	runes := []rune(field)
	if len(runes) == 0 {
		return false
	}
	// check whether first rune can start an identifier name in Java
	// Java identifier start = [Lu]|[Ll]|[Lt]|[Lm]|[Lo]|[Nl]|[Sc]|[Pc]
	// see https://developer.classpath.org/doc/java/lang/Character-source.html
	// line 3295
	r := runes[0]
	return unicode.Is(unicode.Lu, r) ||
		unicode.Is(unicode.Ll, r) || unicode.Is(unicode.Lt, r) ||
		unicode.Is(unicode.Lm, r) || unicode.Is(unicode.Lo, r) ||
		unicode.Is(unicode.Nl, r) ||
		unicode.Is(unicode.Sc, r) || unicode.Is(unicode.Pc, r)
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
		case manifest.Main.MustGet("Name") != "":
			// Manifest original spec...
			return manifest.Main.MustGet("Name")
		case manifest.Main.MustGet("Bundle-Name") != "":
			// BND tooling... TODO: this does not seem accurate (I don't see a reference in the BND tooling docs for this)
			return manifest.Main.MustGet("Bundle-Name")
		case manifest.Main.MustGet("Short-Name") != "":
			// Jenkins...
			return manifest.Main.MustGet("Short-Name")
		case manifest.Main.MustGet("Extension-Name") != "":
			// Jenkins...
			return manifest.Main.MustGet("Extension-Name")
		case manifest.Main.MustGet("Implementation-Title") != "":
			// last ditch effort...
			return manifest.Main.MustGet("Implementation-Title")
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
	if value := manifest.Main.MustGet(fieldName); value != "" {
		return value
	}

	for _, section := range manifest.Sections {
		if value := section.MustGet(fieldName); value != "" {
			return value
		}
	}

	return ""
}
