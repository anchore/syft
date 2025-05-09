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

type Candidate struct {
	Value    string
	Contents file.LocationReadCloser // this is for cases where we know we have license content and want to do analysis
	Location file.Location           // this is for cases where we just want the metadata file location
}

type LicenseBuilder struct {
	candidates []Candidate
	contents   []file.LocationReadCloser
	tp         license.Type
}

func NewLicenseBuilder() *LicenseBuilder {
	return &LicenseBuilder{
		candidates: make([]Candidate, 0),
		contents:   make([]file.LocationReadCloser, 0),
		tp:         license.Declared,
	}
}

func (b *LicenseBuilder) WithValues(expr ...string) *LicenseBuilder {
	candidates := candidatesFromExpr(expr)
	b.candidates = append(b.candidates, candidates...)
	return b
}

func (b *LicenseBuilder) WithCandidates(candidates ...Candidate) *LicenseBuilder {
	b.candidates = append(b.candidates, candidates...)
	return b
}

func candidatesFromExpr(expr []string) []Candidate {
	candidates := make([]Candidate, 0)
	for _, expr := range expr {
		candidates = append(candidates, Candidate{
			Value: expr,
		})
	}
	return candidates
}

func (b *LicenseBuilder) WithContents(contents ...file.LocationReadCloser) *LicenseBuilder {
	b.contents = append(b.contents, contents...)
	return b
}

func (b *LicenseBuilder) WithType(t license.Type) *LicenseBuilder {
	b.tp = t
	return b
}

func (b *LicenseBuilder) Build(ctx context.Context) []License {
	output := make([]License, 0)
	if len(b.candidates) == 0 && len(b.contents) == 0 {
		return output // we have no inputs that could make any licenses; return empty list
	}

	// let's go through our candidates and make sure non of them are full license texts!
	var filtered []Candidate
	for _, l := range b.candidates {
		if strings.Contains(l.Value, "\n") {
			// we want to add a new content item and remove the bad value
			b.contents = append(b.contents, file.LocationReadCloser{
				Location:   file.Location{},
				ReadCloser: io.NopCloser(strings.NewReader(l.Value)),
			})
		} else {
			filtered = append(filtered, l)
		}
	}
	// now we're sure that our value:contents pairings are not contents:contents
	b.candidates = filtered

	// values present so easy output construction
	for _, l := range b.candidates {
		output = append(output, b.buildFromCandidate(l)...)
	}

	// we have some readers (with no values) that we've been asked to turn into licenses if we can
	for _, content := range b.contents {
		output = append(output, b.buildFromContents(ctx, content)...)
	}

	return output
}

// Question - if a candidate is provided with a value do we still want the scanner to search for additional ID?
func (b *LicenseBuilder) buildFromCandidate(c Candidate) []License {
	content := ""
	if c.Contents.ReadCloser != nil {
		var err error
		content, err = contentFromReader(c.Contents)
		if err != nil {
			log.WithFields("error", err, "path", c.Contents.Path()).Trace("could not read content from path")
		}
	}
	output := License{
		Value:    c.Value,
		Contents: content,
		Type:     b.tp,
	}

	// we'll never have both c.Contents and c.Location
	// these fields should always be mutually exclusive
	// contents is for the scanner, location is for where we read the metadata
	if c.Contents.Location.Path() != "" {
		output.Locations = file.NewLocationSet(c.Contents.Location)
	}

	if c.Location.Path() != "" {
		output.Locations = file.NewLocationSet(c.Location)
	}

	if ex, err := license.ParseExpression(c.Value); err == nil {
		output.SPDXExpression = ex
	}

	return []License{output}
}

func (b *LicenseBuilder) buildFromContents(ctx context.Context, contents file.LocationReadCloser) []License {
	scanner, err := licenses.ContextLicenseScanner(ctx)
	if err != nil {
		internal, err := contentFromReader(contents)
		if err != nil {
			log.WithFields("error", err, "path", contents.Path()).Trace("could not read content")
			return nil
		}
		// we have no scanner so we sha256 the content and value populated
		return []License{b.licenseFromContentHash(internal, contents.Location)}
	}

	evidence, content, err := scanner.FindEvidence(ctx, contents)
	if err != nil {
		log.WithFields("error", err, "path", contents.Path()).Trace("scanner failed")
		return nil
	}

	if len(evidence) > 0 {
		// we have some ID and offsets to apply to our content; let's make some detailed licenses
		return b.licensesFromEvidenceAndContent(evidence, []byte(content), contents.Location)
	}
	// scanner couldn't find anything, but we still have the file contents; sha256 and send it back with value
	return []License{b.licenseFromContentHash(string(content), contents.Location)}
}

func (b *LicenseBuilder) licensesFromEvidenceAndContent(evidence []licenses.Evidence, content []byte, location file.Location) []License {
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
		candidate.Locations = file.NewLocationSet(location)
		licenses = append(licenses, candidate)
	}
	return licenses
}

func (b *LicenseBuilder) licenseFromContentHash(content string, location file.Location) License {
	hash := sha256HexFromString(content)
	value := "LicenseRef-sha256:" + hash

	return License{
		Value:     value,
		Contents:  content,
		Type:      b.tp,
		Locations: file.NewLocationSet(location),
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
