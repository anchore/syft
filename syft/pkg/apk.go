package pkg

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/go-viper/mapstructure/v2"
	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/syft/file"
)

const ApkDBGlob = "**/lib/apk/db/installed"

var _ FileOwner = (*ApkDBEntry)(nil)

// ApkDBEntry represents all captured data for the alpine linux package manager flat-file store.
// See the following sources for more information:
// - https://wiki.alpinelinux.org/wiki/Apk_spec
// - https://git.alpinelinux.org/apk-tools/tree/src/package.c
// - https://git.alpinelinux.org/apk-tools/tree/src/database.c
type ApkDBEntry struct {
	// Package is the package name as found in the installed file
	Package string `mapstructure:"P" json:"package"`

	// OriginPackage is the original source package name this binary was built from (used to track which aport/source built this)
	OriginPackage string `mapstructure:"o" json:"originPackage" cyclonedx:"originPackage"`

	// Maintainer is the package maintainer name and email
	Maintainer string `mapstructure:"m" json:"maintainer"`

	// Version is the package version as found in the installed file
	Version string `mapstructure:"V" json:"version"`

	// Architecture is the target CPU architecture
	Architecture string `mapstructure:"A" json:"architecture"`

	// URL is the upstream project URL
	URL string `mapstructure:"U" json:"url"`

	// Description is a human-readable package description
	Description string `mapstructure:"T" json:"description"`

	// Size is the package archive size in bytes (.apk file size)
	Size int `mapstructure:"S" json:"size" cyclonedx:"size"`

	// InstalledSize is the total size of installed files in bytes
	InstalledSize int `mapstructure:"I" json:"installedSize" cyclonedx:"installedSize"`

	// Dependencies are the runtime dependencies required by this package
	Dependencies []string `mapstructure:"D" json:"pullDependencies" cyclonedx:"pullDependencies"`

	// Provides are virtual packages provided by this package (for capability-based dependencies)
	Provides []string `mapstructure:"p" json:"provides" cyclonedx:"provides"`

	// Checksum is the package content checksum for integrity verification
	Checksum string `mapstructure:"C" json:"pullChecksum" cyclonedx:"pullChecksum"`

	// GitCommit is the git commit hash of the APK port definition in Alpine's aports repository
	GitCommit string `mapstructure:"c" json:"gitCommitOfApkPort" cyclonedx:"gitCommitOfApkPort"`

	// Files are the files installed by this package
	Files []ApkFileRecord `json:"files"`
}

// spaceDelimitedStringSlice is an internal helper type for unmarshaling space-delimited strings from JSON into a string slice.
type spaceDelimitedStringSlice []string

func (m *ApkDBEntry) UnmarshalJSON(data []byte) error {
	var fields []reflect.StructField
	t := reflect.TypeOf(ApkDBEntry{})
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.Name == "Dependencies" {
			f.Type = reflect.TypeOf(spaceDelimitedStringSlice{})
		}
		fields = append(fields, f)
	}
	apkMetadata := reflect.StructOf(fields)
	inst := reflect.New(apkMetadata)
	if err := json.Unmarshal(data, inst.Interface()); err != nil {
		return err
	}

	return mapstructure.Decode(inst.Elem().Interface(), m)
}

func (a *spaceDelimitedStringSlice) UnmarshalJSON(data []byte) error {
	var jsonObj interface{}

	if err := json.Unmarshal(data, &jsonObj); err != nil {
		return err
	}

	switch obj := jsonObj.(type) {
	case string:
		if obj == "" {
			*a = nil
		} else {
			*a = strings.Split(obj, " ")
		}
		return nil
	case []interface{}:
		s := make([]string, 0, len(obj))
		for _, v := range obj {
			value, ok := v.(string)
			if !ok {
				return fmt.Errorf("invalid type for string array element: %T", v)
			}
			s = append(s, value)
		}
		*a = s
		return nil
	case nil:
		return nil
	default:
		return fmt.Errorf("invalid type for string array: %T", obj)
	}
}

// ApkFileRecord represents a single file listing and metadata from a APK DB entry (which may have many of these file records).
type ApkFileRecord struct {
	// Path is the file path relative to the filesystem root
	Path string `json:"path"`

	// OwnerUID is the file owner user ID
	OwnerUID string `json:"ownerUid,omitempty"`

	// OwnerGID is the file owner group ID
	OwnerGID string `json:"ownerGid,omitempty"`

	// Permissions is the file permission mode string (e.g. "0755", "0644")
	Permissions string `json:"permissions,omitempty"`

	// Digest is the file content hash for integrity verification
	Digest *file.Digest `json:"digest,omitempty"`
}

func (m ApkDBEntry) OwnedFiles() (result []string) {
	s := strset.New()
	for _, f := range m.Files {
		if f.Path != "" {
			s.Add(f.Path)
		}
	}
	result = s.List()
	sort.Strings(result)
	return result
}
