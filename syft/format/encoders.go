package format

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/format/github"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	"github.com/anchore/syft/syft/format/syftjson"
	"github.com/anchore/syft/syft/format/table"
	"github.com/anchore/syft/syft/format/template"
	"github.com/anchore/syft/syft/format/text"
	"github.com/anchore/syft/syft/sbom"
)

// DefaultEncoders returns the latest encoders for each format with all default options.
func DefaultEncoders() []sbom.FormatEncoder {
	// encoders that support a single version
	encs := []sbom.FormatEncoder{
		syftjson.DefaultFormatEncoder(),
		github.DefaultFormatEncoder(),
		table.DefaultFormatEncoder(),
		text.DefaultFormatEncoder(),
		template.DefaultFormatEncoder(),
	}

	// encoders that support multiple versions
	encs = append(encs, cyclonedxxml.DefaultFormatEncoders()...)
	encs = append(encs, cyclonedxjson.DefaultFormatEncoders()...)
	encs = append(encs, spdxtagvalue.DefaultFormatEncoders()...)
	encs = append(encs, spdxjson.DefaultFormatEncoders()...)

	return encs
}

type EncoderCollection struct {
	encoders []sbom.FormatEncoder
}

func NewEncoderCollection(encoders ...sbom.FormatEncoder) *EncoderCollection {
	return &EncoderCollection{
		encoders: encoders,
	}
}

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

func (e EncoderCollection) Aliases() []string {
	aliases := strset.New()
	for _, f := range e.encoders {
		aliases.Add(f.Aliases()...)
	}
	lst := aliases.List()
	sort.Strings(lst)
	return lst
}

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
