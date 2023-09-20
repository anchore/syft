package formats

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strings"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/formats/cyclonedxjson"
	"github.com/anchore/syft/syft/formats/cyclonedxxml"
	"github.com/anchore/syft/syft/formats/github"
	"github.com/anchore/syft/syft/formats/spdxjson"
	"github.com/anchore/syft/syft/formats/spdxtagvalue"
	"github.com/anchore/syft/syft/formats/syftjson"
	"github.com/anchore/syft/syft/formats/table"
	"github.com/anchore/syft/syft/formats/template"
	"github.com/anchore/syft/syft/formats/text"
	"github.com/anchore/syft/syft/sbom"
)

func Formats() []sbom.Format {
	return []sbom.Format{
		syftjson.Format(),
		github.Format(),
		table.Format(),
		text.Format(),
		template.Format(),
		cyclonedxxml.Format1_0(),
		cyclonedxxml.Format1_1(),
		cyclonedxxml.Format1_2(),
		cyclonedxxml.Format1_3(),
		cyclonedxxml.Format1_4(),
		cyclonedxxml.Format1_5(),
		cyclonedxjson.Format1_0(),
		cyclonedxjson.Format1_1(),
		cyclonedxjson.Format1_2(),
		cyclonedxjson.Format1_3(),
		cyclonedxjson.Format1_4(),
		cyclonedxjson.Format1_5(),
		spdxtagvalue.Format2_1(),
		spdxtagvalue.Format2_2(),
		spdxtagvalue.Format2_3(),
		spdxjson.Format2_2(),
		spdxjson.Format2_3(),
	}
}

func Identify(by []byte) sbom.Format {
	for _, f := range Formats() {
		if err := f.Validate(bytes.NewReader(by)); err != nil {
			if !errors.Is(err, sbom.ErrValidationNotSupported) {
				log.WithFields("error", err).Tracef("format validation for %s failed", f.ID())
			}
			continue
		}
		return f
	}
	return nil
}

// ByName accepts a name@version string, such as:
//
//	spdx-json@2.1 or cyclonedx@1.5
func ByName(name string) sbom.Format {
	parts := strings.SplitN(name, "@", 2)
	version := sbom.AnyVersion
	if len(parts) > 1 {
		version = parts[1]
	}
	return ByNameAndVersion(parts[0], version)
}

func ByNameAndVersion(name string, version string) sbom.Format {
	name = cleanFormatName(name)
	var mostRecentFormat sbom.Format
	for _, f := range Formats() {
		for _, n := range f.IDs() {
			if cleanFormatName(string(n)) == name && versionMatches(f.Version(), version) {
				// if the version is not specified and the format is cyclonedx, then we want to return the most recent version up to 1.4
				// If more aliases like cdx are added this will not catch those - we want to eventually provide a way for
				// formats to inform this function what their default version is
				// TODO: remove this check when 1.5 is stable or default formats are designed. PR below should be merged.
				// https://github.com/CycloneDX/cyclonedx-go/pull/90
				if version == sbom.AnyVersion && strings.Contains(string(n), "cyclone") {
					if f.Version() == "1.5" {
						continue
					}
				}
				if mostRecentFormat == nil || f.Version() > mostRecentFormat.Version() {
					mostRecentFormat = f
				}
			}
		}
	}
	return mostRecentFormat
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
func Encode(s sbom.SBOM, f sbom.Format) ([]byte, error) {
	buff := bytes.Buffer{}

	if err := f.Encode(&buff, s); err != nil {
		return nil, fmt.Errorf("unable to encode sbom: %w", err)
	}

	return buff.Bytes(), nil
}

// Decode takes a reader for an SBOM and generates all internal SBOM elements.
func Decode(reader io.Reader) (*sbom.SBOM, sbom.Format, error) {
	by, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read sbom: %w", err)
	}

	f := Identify(by)
	if f == nil {
		return nil, nil, fmt.Errorf("unable to identify format")
	}

	s, err := f.Decode(bytes.NewReader(by))
	return s, f, err
}

func AllIDs() (ids []sbom.FormatID) {
	for _, f := range Formats() {
		if slices.Contains(ids, f.ID()) {
			continue
		}
		ids = append(ids, f.ID())
	}
	return ids
}
