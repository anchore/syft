package java

import (
	"path/filepath"
	"regexp"
	"strings"

	"github.com/anchore/imgbom/imgbom/pkg"
)

// match examples:
//	pkg-extra-field-4.3.2-rc1 --> match(name=pkg-extra-field version=4.3.2-rc1)
//	pkg-extra-field-4.3-rc1   --> match(name=pkg-extra-field version=4.3-rc1)
//	pkg-extra-field-4.3       --> match(name=pkg-extra-field version=4.3)
var versionPattern = regexp.MustCompile(`(?P<name>.+)-(?P<version>(\d+\.)?(\d+\.)?(\*|\d+)(-[a-zA-Z0-9\-\.]+)*)`)

type archiveFilename struct {
	raw string
}

func newJavaArchiveFilename(raw string) archiveFilename {
	return archiveFilename{
		raw: raw,
	}
}

func (a archiveFilename) normalize() string {
	// trim the file extension and remove any path prefixes
	return strings.TrimSuffix(filepath.Base(a.raw), "."+a.extension())
}

func (a archiveFilename) fields() []map[string]string {
	name := a.normalize()

	matches := versionPattern.FindAllStringSubmatch(name, -1)
	items := make([]map[string]string, 0)
	for _, match := range matches {
		item := make(map[string]string)
		for i, name := range versionPattern.SubexpNames() {
			if i != 0 && name != "" {
				item[name] = match[i]
			}
		}
		items = append(items, item)
	}
	return items
}

func (a archiveFilename) extension() string {
	return strings.TrimPrefix(filepath.Ext(a.raw), ".")
}

func (a archiveFilename) pkgType() pkg.Type {
	switch strings.ToLower(a.extension()) {
	case "jar":
		return pkg.JarPkg
	case "war":
		return pkg.WarPkg
	case "ear":
		return pkg.EarPkg
	case "jpi":
		return pkg.JpiPkg
	case "hpi":
		return pkg.HpiPkg
	default:
		return pkg.UnknownPkg
	}
}

func (a archiveFilename) version() string {
	fields := a.fields()

	// there should be only one version, if there is more or less then something is wrong
	if len(fields) != 1 {
		return ""
	}

	return fields[0]["version"]
}

func (a archiveFilename) name() string {
	fields := a.fields()

	// there should be only one name, if there is more or less then something is wrong
	if len(fields) != 1 {
		return ""
	}

	return fields[0]["name"]
}
