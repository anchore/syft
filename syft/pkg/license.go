package pkg

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/scylladb/go-set/strset"
	"io"
	"net/url"
	"sort"
	"strings"
)

var _ sort.Interface = (*Licenses)(nil)

// License represents an SPDX Expression or license value extracted from a package's metadata
// We want to hash ignore URLs and Location since we merge these fields across equal licenses.
// We also Ignore hashing contents here. - when missing value/expression, put in "LicenseRef-sha256:xxxx..." as the value

// The Declared License is what the authors of a project believe govern the package. This is the default type syft declares.
// A Concluded License type is the license the SBOM creator believes governs the package (human crafted or altered SBOM)

// TODO: we want a new field that can express the license requirements imposed by a license or group of licenses.
type License struct {
	SPDXExpression string
	Value          string
	Contents       string `hash:"ignore"`
	Type           license.Type
	URLs           []string         `hash:"ignore"`
	Locations      file.LocationSet `hash:"ignore"`
}

func (s License) Empty() bool {
	return s.Value == "" && s.SPDXExpression == ""
}

// Merge two licenses into a new license object. If the merge is not possible due to unmergeable fields
// (e.g. different values for Value, SPDXExpression, Type, or any non-collection type) an error is returned.
// TODO: this is a bit of a hack to not infinitely recurse when hashing a license
func (s License) Merge(l License) (*License, error) {
	sHash, err := artifact.IDByHash(s)
	if err != nil {
		return nil, err
	}
	lHash, err := artifact.IDByHash(l)
	if err != nil {
		return nil, err
	}
	if sHash != lHash {
		return nil, fmt.Errorf("cannot merge licenses with different hash")
	}

	// try to keep s.URLs unallocated unless necessary (which is the default state from the constructor)
	if len(l.URLs) > 0 {
		s.URLs = append(s.URLs, l.URLs...)
	}

	if len(s.URLs) > 0 {
		s.URLs = strset.New(s.URLs...).List()
		sort.Strings(s.URLs)
	}

	if l.Locations.Empty() {
		return &s, nil
	}

	// since the set instance has a reference type (map) we must make a new instance
	locations := file.NewLocationSet(s.Locations.ToSlice()...)
	locations.Add(l.Locations.ToSlice()...)
	s.Locations = locations

	return &s, nil
}

type Licenses []License

func (l Licenses) Len() int {
	return len(l)
}

func (l Licenses) Less(i, j int) bool {
	if l[i].Value == l[j].Value {
		if l[i].SPDXExpression == l[j].SPDXExpression {
			if l[i].Type == l[j].Type {
				if l[i].Contents == l[j].Contents {
					// While URLs and location are not exclusive fields
					// returning true here reduces the number of swaps
					// while keeping a consistent sort order of
					// the order that they appear in the list initially
					// If users in the future have preference to sorting based
					// on the slice representation of either field we can update this code
					return true
				}
				return l[i].Contents < l[j].Contents
			}
			return l[i].Type < l[j].Type
		}
		return l[i].SPDXExpression < l[j].SPDXExpression
	}
	return l[i].Value < l[j].Value
}

func (l Licenses) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

type LicenseBuilder struct {
	value     string
	tp        license.Type
	locations file.LocationSet
	content   file.LocationReadCloser
}

func NewLicenseBuilder() *LicenseBuilder {
	return &LicenseBuilder{
		locations: file.NewLocationSet(),
		tp:        license.Declared,
	}
}
func (b *LicenseBuilder) WithValue(expr string) *LicenseBuilder {
	b.value = expr
	return b
}

func (b *LicenseBuilder) WithContents(contents file.LocationReadCloser) *LicenseBuilder {
	b.content = contents
	b.locations.Add(contents.Location)
	return b
}

func (b *LicenseBuilder) WithType(t license.Type) *LicenseBuilder {
	b.tp = t
	return b
}

func (b *LicenseBuilder) WithLocation(location file.Location) *LicenseBuilder {
	b.locations.Add(location)
	return b
}

func (b *LicenseBuilder) Build(ctx context.Context) []License {
	if b.value == "" && b.content.ReadCloser == nil {
		return nil // no inputs at all
	}

	// If value looks like full text (contains newline), treat it as content and zero the value
	if strings.Contains(b.value, "\n") {
		b.content = file.LocationReadCloser{
			Location:   file.Location{},
			ReadCloser: io.NopCloser(strings.NewReader(b.value)),
		}
		b.value = ""
	}

	// value present; easy license construction
	if b.value != "" {
		return b.buildFromValue()
	}

	// Case 2: Only contents provided — scan for licenses
	return b.buildFromContents(ctx)
}

func (b *LicenseBuilder) buildFromValue() []License {
	content := ""
	if b.content.ReadCloser != nil {
		var err error
		content, err = contentFromReader(b.content)
		if err != nil {
			log.WithFields("error", err, "path", b.content.Path()).Trace("could not read content from path")
		}
	}

	candidate := License{
		Value:     b.value,
		Contents:  content,
		Type:      b.tp,
		Locations: b.locations,
	}

	if ex, err := license.ParseExpression(b.value); err == nil {
		candidate.SPDXExpression = ex
	}

	return []License{candidate}
}

func (b *LicenseBuilder) buildFromContents(ctx context.Context) []License {
	scanner, err := licenses.ContextLicenseScanner(ctx)
	if err != nil {
		contents, err := contentFromReader(b.content)
		if err != nil {
			log.WithFields("error", err, "path", b.content.Path()).Trace("could not read content")
			return nil
		}
		// we have no scanner so we sha256 the content and value populated
		return []License{b.licenseFromContentHash(contents)}
	}

	evidence, content, err := scanner.FindEvidence(ctx, b.content)
	if err != nil {
		log.WithFields("error", err, "path", b.content.Path()).Trace("scanner failed")
		return nil
	}

	if len(evidence) > 0 {
		return b.licensesFromEvidenceAndContent(evidence, []byte(content))
	}
	return []License{b.licenseFromContentHash(string(content))}
}

func (b *LicenseBuilder) licensesFromEvidenceAndContent(evidence []licenses.Evidence, content []byte) []License {
	licenses := make([]License, 0)
	for _, e := range evidence {
		// basic license
		candidate := License{
			Value: e.ID,
		}
		// get content offset
		if e.Start >= 0 && e.End <= len(content) && e.Start <= e.End {
			candidate.Contents = string(content[e.Start:e.End])
		}
		// check for SPDX Validity
		if ex, err := license.ParseExpression(e.ID); err == nil {
			candidate.SPDXExpression = ex
		}

		// add other builder values that don't change between licenses for single content
		candidate.Type = b.tp
		candidate.Locations = b.locations
		licenses = append(licenses, candidate)
	}
	return licenses
}

func (b *LicenseBuilder) licenseFromContentHash(content string) License {
	hash := sha256HexFromString(content)
	value := "LicenseRef-sha256:" + hash

	return License{
		Value:     value,
		Contents:  content,
		Type:      b.tp,
		Locations: b.locations,
	}
}

func contentFromReader(r io.Reader) (string, error) {
	bytes, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func sha256HexFromString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}

func stripUnwantedCharacters(rawURL string) (string, error) {
	cleanedURL := strings.TrimSpace(rawURL)
	_, err := url.ParseRequestURI(cleanedURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	return cleanedURL, nil
}
