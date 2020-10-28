package java

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/syft/internal/log"

	"github.com/anchore/syft/syft/pkg"
)

// match examples:
//	pkg-extra-field-4.3.2-rc1 --> match(name=pkg-extra-field version=4.3.2-rc1)
//	pkg-extra-field-4.3-rc1   --> match(name=pkg-extra-field version=4.3-rc1)
//	pkg-extra-field-4.3       --> match(name=pkg-extra-field version=4.3)
var versionPattern = regexp.MustCompile(`(?P<name>.+)-(?P<version>(\d+\.)?(\d+\.)?(\*|\d+)(-[a-zA-Z0-9\-\.]+)*)`)

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
		log.Errorf("discovered multiple name-version pairings from %q: %+v", a.raw, a.fields)
		return ""
	} else if len(a.fields) < 1 {
		return ""
	}

	return a.fields[0]["version"]
}

func (a archiveFilename) name() string {
	for _, fieldSet := range a.fields {
		if name, ok := fieldSet["name"]; ok {
			// return the first name
			return name
		}
	}

	// derive the name from the archive name (no path or extension)
	basename := filepath.Base(a.raw)
	return strings.TrimSuffix(basename, filepath.Ext(basename))
}
