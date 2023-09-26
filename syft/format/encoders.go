package format

import (
	"bytes"
	"fmt"
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
	"github.com/scylladb/go-set/strset"
	"regexp"
	"sort"
	"strings"
)

// DefaultEncoders returns the latest encoders for each format with all default options.
func DefaultEncoders() []sbom.FormatEncoder {
	return []sbom.FormatEncoder{
		syftjson.DefaultFormatEncoder(),
		github.DefaultFormatEncoder(),
		table.DefaultFormatEncoder(),
		text.DefaultFormatEncoder(),
		template.DefaultFormatEncoder(),
		cyclonedxxml.DefaultFormatEncoder(),
		cyclonedxjson.DefaultFormatEncoder(),
		spdxtagvalue.DefaultFormatEncoder(),
		spdxjson.DefaultFormatEncoder(),
	}
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
	var ids []sbom.FormatID
	for _, f := range e.encoders {
		ids = append(ids, f.ID())
	}
	return ids
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

	name = cleanFormatName(name)
	var mostRecentFormat sbom.FormatEncoder

	for _, f := range e.encoders {
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
