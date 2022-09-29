package pkg

import (
	"strings"

	"github.com/anchore/packageurl-go"
	"github.com/anchore/syft/syft/linux"
)

type ConanLockMetadata struct {
	Ref            string            `json:"ref"`
	PackageID      string            `json:"package_id,omitempty"`
	Prev           string            `json:"prev,omitempty"`
	Requires       string            `json:"requires,omitempty"`
	BuildRequires  string            `json:"build_requires,omitempty"`
	PythonRequires string            `json:"py_requires,omitempty"`
	Options        map[string]string `json:"options,omitempty"`
	Path           string            `json:"path,omitempty"`
	Context        string            `json:"context,omitempty"`
}

func (m ConanLockMetadata) PackageURL(_ *linux.Release) string {
	var qualifiers packageurl.Qualifiers

	name, version := m.NameAndVersion()

	return packageurl.NewPackageURL(
		packageurl.TypeConan,
		"",
		name,
		version,
		qualifiers,
		"",
	).ToString()
}

// NameAndVersion returns the name and version of the package.
// If ref is not in the format of "name/version@user/channel", then an empty string is returned for both.
func (m ConanLockMetadata) NameAndVersion() (name, version string) {
	if len(m.Ref) < 1 {
		return name, version
	}

	splits := strings.Split(strings.Split(m.Ref, "@")[0], "/")
	if len(splits) < 2 {
		return name, version
	}

	return splits[0], splits[1]
}
