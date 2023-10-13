package format

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/sbom"
)

type EncoderCollection struct {
	encoders []sbom.FormatEncoder
}

func NewEncoderCollection(encoders ...sbom.FormatEncoder) *EncoderCollection {
	return &EncoderCollection{
		encoders: encoders,
	}
}

// IDs returns all format IDs represented in the collection.
func (e EncoderCollection) IDs() []sbom.FormatID {
	idSet := strset.New()
	for _, f := range e.encoders {
		idSet.Add(string(f.ID()))
	}

	idList := idSet.List()
	sort.Strings(idList)

	var ids []sbom.FormatID
	for _, id := range idList {
		ids = append(ids, sbom.FormatID(id))
	}

	return ids
}

// NameVersions returns all formats that are supported by the collection as a list of "name@version" strings.
func (e EncoderCollection) NameVersions() []string {
	set := strset.New()
	for _, f := range e.encoders {
		if f.Version() == sbom.AnyVersion {
			set.Add(string(f.ID()))
		} else {
			set.Add(fmt.Sprintf("%s@%s", f.ID(), f.Version()))
		}
	}

	list := set.List()
	sort.Strings(list)

	return list
}

// Aliases returns all format aliases represented in the collection (where an ID would be "spdx-tag-value" the alias would be "spdx").
func (e EncoderCollection) Aliases() []string {
	aliases := strset.New()
	for _, f := range e.encoders {
		aliases.Add(f.Aliases()...)
	}
	lst := aliases.List()
	sort.Strings(lst)
	return lst
}

// Get returns the contained encoder for a given format name and version.
func (e EncoderCollection) Get(name string, version string) sbom.FormatEncoder {
	log.WithFields("name", name, "version", version).Trace("looking for matching encoder")

	name = cleanFormatName(name)
	var mostRecentFormat sbom.FormatEncoder

	for _, f := range e.encoders {
		log.WithFields("name", f.ID(), "version", f.Version(), "aliases", f.Aliases()).Trace("considering format")
		names := []string{string(f.ID())}
		names = append(names, f.Aliases()...)
		for _, n := range names {
			if cleanFormatName(n) == name && versionMatches(f.Version(), version) {
				if mostRecentFormat == nil || f.Version() > mostRecentFormat.Version() {
					mostRecentFormat = f
				}
			}
		}
	}

	if mostRecentFormat != nil {
		log.WithFields("name", mostRecentFormat.ID(), "version", mostRecentFormat.Version()).Trace("found matching encoder")
	} else {
		log.WithFields("search-name", name, "search-version", version).Trace("no matching encoder found")
	}

	return mostRecentFormat
}

// GetByString accepts a name@version string, such as:
//   - json
//   - spdx-json@2.1
//   - cdx@1.5
func (e EncoderCollection) GetByString(s string) sbom.FormatEncoder {
	parts := strings.SplitN(s, "@", 2)
	version := sbom.AnyVersion
	if len(parts) > 1 {
		version = parts[1]
	}
	return e.Get(parts[0], version)
}

func versionMatches(version string, match string) bool {
	if version == sbom.AnyVersion || match == sbom.AnyVersion {
		return true
	}

	match = strings.ReplaceAll(match, ".", "\\.")
	match = strings.ReplaceAll(match, "*", ".*")
	match = fmt.Sprintf("^%s(\\..*)*$", match)
	matcher, err := regexp.Compile(match)
	if err != nil {
		return false
	}
	return matcher.MatchString(version)
}

func cleanFormatName(name string) string {
	r := strings.NewReplacer("-", "", "_", "")
	return strings.ToLower(r.Replace(name))
}

// Encode takes all SBOM elements and a format option and encodes an SBOM document.
func Encode(s sbom.SBOM, f sbom.FormatEncoder) ([]byte, error) {
	buff := bytes.Buffer{}

	if err := f.Encode(&buff, s); err != nil {
		return nil, fmt.Errorf("unable to encode sbom: %w", err)
	}

	return buff.Bytes(), nil
}
