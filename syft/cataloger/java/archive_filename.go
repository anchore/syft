package java

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/syft/syft/pkg"
)

// match on versions and anything after the version. This is used to isolate the name from the version.
// match examples:
// wagon-webdav-1.0.2-rc1-hudson.jar      --->     -1.0.2-rc1-hudson.jar
// windows-remote-command-1.0.jar         --->     -1.0.jar
// wstx-asl-1-2.jar                       --->     -1-2.jar
// guava-rc0.jar                          --->     -rc0.jar
var versionAreaPattern = regexp.MustCompile(`-(?P<version>(\d+\.)?(\d+\.)?(r?c?\d+)(-[a-zA-Z0-9\-.]+)*)(?P<remaining>.*)$`)

// match on explicit versions. This is used for extracting version information.
// match examples:
//	pkg-extra-field-4.3.2-rc1 --> match(name=pkg-extra-field version=4.3.2-rc1)
//	pkg-extra-field-4.3-rc1   --> match(name=pkg-extra-field version=4.3-rc1)
//	pkg-extra-field-4.3       --> match(name=pkg-extra-field version=4.3)
var versionPattern = regexp.MustCompile(`-(?P<version>(\d+\.)?(\d+\.)?(r?c?\d+)(-[a-zA-Z0-9\-.]+)*)`)

type archiveFilename struct {
	raw    string
	fields []map[string]string
}

func newJavaArchiveFilename(raw string) archiveFilename {
	// trim the file extension and remove any path prefixes
	name := strings.TrimSuffix(filepath.Base(raw), filepath.Ext(raw))

	matches := versionPattern.FindAllStringSubmatch(name, -1)
	fields := make([]map[string]string, 0)
	for _, match := range matches {
		item := make(map[string]string)
		for i, name := range versionPattern.SubexpNames() {
			if i != 0 && name != "" {
				item[name] = match[i]
			}
		}
		fields = append(fields, item)
	}

	return archiveFilename{
		raw:    raw,
		fields: fields,
	}
}

func (a archiveFilename) extension() string {
	return strings.TrimPrefix(filepath.Ext(a.raw), ".")
}

func (a archiveFilename) pkgType() pkg.Type {
	switch strings.ToLower(a.extension()) {
	case "jar", "war", "ear":
		return pkg.JavaPkg
	case "jpi", "hpi":
		return pkg.JenkinsPluginPkg
	default:
		return pkg.UnknownPkg
	}
}

func (a archiveFilename) version() string {
	if len(a.fields) > 1 {
		log.Warnf("discovered multiple name-version pairings from %q: %+v", a.raw, a.fields)
		return ""
	} else if len(a.fields) < 1 {
		return ""
	}

	return a.fields[0]["version"]
}

func (a archiveFilename) name() string {
	// derive the name from the archive name (no path or extension) and remove any versions found
	basename := filepath.Base(a.raw)
	cleaned := strings.TrimSuffix(basename, filepath.Ext(basename))
	return versionAreaPattern.ReplaceAllString(cleaned, "")
}
