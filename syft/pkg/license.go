package pkg

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"
	"golang.org/x/net/context"

	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
)

var _ sort.Interface = (*Licenses)(nil)

// License represents an SPDX Expression or license value extracted from a package's metadata
// We want to ignore URLs and Location since we merge these fields across equal licenses.
// A License is a unique combination of value, expression and type, where
// its sources are always considered merged and additions to the evidence
// of where it was found and how it was sourced.
// This is different from how we treat a package since we consider package paths
// in order to distinguish if packages should be kept separate
// this is different for licenses since we're only looking for evidence
// of where a license was declared/concluded for a given package
// If a license is given as it's full text in the metadata rather than it's value or SPDX expression
// The Contents field is used to represent this data
// A Concluded License type is the license the SBOM creator believes governs the package (human crafted or altered SBOM)
// The Declared License is what the authors of a project believe govern the package. This is the default type syft declares.
type License struct {
	SPDXExpression string
	Value          string
	Type           license.Type
	// we want to ignore the contents here so we can drop contents in the post-processing step
	Contents  string           `hash:"ignore"`
	URLs      []string         `hash:"ignore"`
	Locations file.LocationSet `hash:"ignore"`
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
					// If users in the future have a preference to sorting based
					// on the slice representation of either field, we can update this code
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

func NewLicensesFromReadCloserWithContext(ctx context.Context, closer file.LocationReadCloser) (licenses []License) {
	//Definition: The license that the auditor or scanning tool concludes applies, based on the actual contents of the files.
	//Source: Derived from analyzing the source code, license headers, and full license texts in the files.
	// Given we are scanning the contents of the file, we should use the Concluded License type.
	return newLicenseBuilder().withContents(closer).withType(license.Concluded).build(ctx).ToSlice()
}

func NewLicenseWithContext(ctx context.Context, value string) License {
	return NewLicenseFromTypeWithContext(ctx, value, license.Declared)
}

func NewLicenseFromTypeWithContext(ctx context.Context, value string, t license.Type) License {
	lics := newLicenseBuilder().withCandidates(candidatesFromExpr([]string{value})...).withType(t).build(ctx).ToSlice()
	if len(lics) > 0 {
		return lics[0]
	}
	return License{}
}

func NewLicensesFromValuesWithContext(ctx context.Context, values ...string) (licenses []License) {
	return newLicenseBuilder().withValues(values...).build(ctx).ToSlice()
}

func NewLicensesFromLocationWithContext(ctx context.Context, location file.Location, values ...string) (licenses []License) {
	return newLicenseBuilder().withValuesAndLocation(location, values...).build(ctx).ToSlice()
}

func NewLicenseFromLocationsWithContext(ctx context.Context, value string, locations ...file.Location) License {
	lics := newLicenseBuilder().WithLocationsAndValue(value, locations...).build(ctx).ToSlice()
	if len(lics) > 0 {
		return lics[0]
	}
	return License{}
}

func NewLicenseFromURLsWithContext(ctx context.Context, value string, urls ...string) License {
	l := NewLicenseWithContext(ctx, value)
	s := strset.New()
	for _, u := range urls {
		if u != "" {
			sanitizedURL, err := stripUnwantedCharacters(u)
			if err != nil {
				log.Tracef("unable to sanitize url=%q: %s", u, err)
				continue
			}
			s.Add(sanitizedURL)
		}
	}

	l.URLs = s.List()
	sort.Strings(l.URLs)

	return l
}

func stripUnwantedCharacters(rawURL string) (string, error) {
	cleanedURL := strings.TrimSpace(rawURL)
	_, err := url.ParseRequestURI(cleanedURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	return cleanedURL, nil
}

func NewLicenseFromFieldsWithContext(ctx context.Context, value, url string, location *file.Location) License {
	l := NewLicenseWithContext(ctx, value)
	if location != nil {
		l.Locations.Add(*location)
	}
	if url != "" {
		sanitizedURL, err := stripUnwantedCharacters(url)
		if err != nil {
			log.Tracef("unable to sanitize url=%q: %s", url, err)
		} else {
			l.URLs = append(l.URLs, sanitizedURL)
		}
		l.Type = license.Declared
	}

	return l
}

func (s License) Empty() bool {
	return s.Value == "" && s.SPDXExpression == "" && s.Contents == ""
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

	// since the set instance has a reference type (map), we must make a new instance
	locations := file.NewLocationSet(s.Locations.ToSlice()...)
	locations.Add(l.Locations.ToSlice()...)
	s.Locations = locations

	return &s, nil
}

type licenseCandidate struct {
	Value     string
	Type      license.Type            // this is optional; if not set, then use default from builder
	Contents  file.LocationReadCloser // this is for cases where we know we have license content and want to do analysis
	Locations []file.Location         // this is for cases where we just want the metadata file location
}

type licenseBuilder struct {
	candidates []licenseCandidate
	contents   []file.LocationReadCloser
	tp         license.Type
}

func newLicenseBuilder() *licenseBuilder {
	return &licenseBuilder{
		candidates: make([]licenseCandidate, 0),
		contents:   make([]file.LocationReadCloser, 0),
		tp:         license.Declared,
	}
}

func (b *licenseBuilder) withValues(expr ...string) *licenseBuilder {
	candidates := candidatesFromExpr(expr)
	b.candidates = append(b.candidates, candidates...)
	return b
}

func (b *licenseBuilder) withValuesAndLocation(location file.Location, expr ...string) *licenseBuilder {
	for _, ex := range expr {
		b.candidates = append(b.candidates, licenseCandidate{Value: ex, Locations: []file.Location{location}})
	}
	return b
}

func (b *licenseBuilder) WithLocationsAndValue(expr string, locations ...file.Location) *licenseBuilder {
	b.candidates = append(b.candidates, licenseCandidate{Value: expr, Locations: locations})
	return b
}

func (b *licenseBuilder) withCandidates(candidates ...licenseCandidate) *licenseBuilder {
	b.candidates = append(b.candidates, candidates...)
	return b
}

func candidatesFromExpr(expr []string) []licenseCandidate {
	candidates := make([]licenseCandidate, 0)
	for _, expr := range expr {
		if expr == "" {
			continue
		}
		candidates = append(candidates, licenseCandidate{
			Value: expr,
		})
	}
	return candidates
}

func (b *licenseBuilder) withContents(contents ...file.LocationReadCloser) *licenseBuilder {
	b.contents = append(b.contents, contents...)
	return b
}

func (b *licenseBuilder) withType(t license.Type) *licenseBuilder {
	b.tp = t
	return b
}

func (b *licenseBuilder) build(ctx context.Context) LicenseSet {
	output := NewLicenseSet()
	if len(b.candidates) == 0 && len(b.contents) == 0 {
		return output // we have no inputs that could make any licenses; return an empty list
	}

	// let's go through our candidates and make sure none of them are full license texts!
	var filtered []licenseCandidate
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

	// values are present; let's get the easy output construction done first
	for _, l := range b.candidates {
		output.Add(b.buildFromCandidate(l)...)
	}

	// we have some readers (with no values); let's try to turn into licenses if we can
	for _, content := range b.contents {
		output.Add(b.buildFromContents(ctx, content)...)
	}

	return output
}

// Question - if a candidate is provided with content, do we still want the scanner to search for additional ID?
func (b *licenseBuilder) buildFromCandidate(c licenseCandidate) []License {
	content := ""
	if c.Contents.ReadCloser != nil {
		var err error
		content, err = contentFromReader(c.Contents)
		if err != nil {
			log.WithFields("error", err, "path", c.Contents.Path()).Trace("could not read content from path")
		}
	}

	output := License{
		Value:     c.Value,
		Contents:  content,
		Type:      b.tp,
		Locations: file.NewLocationSet(),
	}

	// optional custom type
	if c.Type != "" {
		output.Type = c.Type
	}

	// we'll never have both c.Contents and c.Locations
	// these fields should always be mutually exclusive
	// contents is for the scanner, location is for where we read the metadata
	if c.Contents.Path() != "" {
		output.Locations = file.NewLocationSet(c.Contents.Location)
	}

	for _, l := range c.Locations {
		if l.Path() != "" {
			output.Locations.Add(l)
		}
	}

	if output.Locations.Empty() {
		// we don't even want the empty set
		output = License{
			Value:    output.Value,
			Contents: output.Contents,
			Type:     output.Type,
		}
	}

	// we want to check if the SPDX field should be set
	if ex, err := license.ParseExpression(c.Value); err == nil {
		output.SPDXExpression = ex
	}

	return []License{output}
}

func (b *licenseBuilder) buildFromContents(ctx context.Context, contents file.LocationReadCloser) []License {
	if !licenses.IsContextLicenseScannerSet(ctx) {
		// we do not have a scanner; we don't want to create one; we sha256 the content and populate the value
		internal, err := contentFromReader(contents)
		if err != nil {
			log.WithFields("error", err, "path", contents.Path()).Trace("could not read content")
			return nil
		}
		return []License{b.licenseFromContentHash(internal, contents.Location)}
	}

	scanner, err := licenses.ContextLicenseScanner(ctx)
	if err != nil {
		log.WithFields("error", err).Trace("could not find license scanner")
		internal, err := contentFromReader(contents)
		if err != nil {
			log.WithFields("error", err, "path", contents.Path()).Trace("could not read content")
			return nil
		}
		return []License{b.licenseFromContentHash(internal, contents.Location)}
	}

	evidence, content, err := scanner.FindEvidence(ctx, contents)
	if err != nil {
		log.WithFields("error", err, "path", contents.Path()).Trace("scanner failed to scan contents at path")
		return nil
	}

	if len(evidence) > 0 {
		// we have some ID and offsets to apply to our content; let's make some detailed licenses
		return b.licensesFromEvidenceAndContent(evidence, content, contents.Location)
	}
	// scanner couldn't find anything, but we still have the file contents; sha256 and send it back with value
	return []License{b.licenseFromContentHash(string(content), contents.Location)}
}

func (b *licenseBuilder) licensesFromEvidenceAndContent(evidence []licenses.Evidence, content []byte, location file.Location) []License {
	ls := make([]License, 0)
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

		// add other builder values that don't change between licenses
		candidate.Type = b.tp
		if location.Path() != "" {
			candidate.Locations = file.NewLocationSet(location)
		}
		ls = append(ls, candidate)
	}
	return ls
}

func (b *licenseBuilder) licenseFromContentHash(content string, location file.Location) License {
	hash := sha256HexFromString(content)
	value := "LicenseRef-sha256:" + hash

	lic := License{
		Value:    value,
		Contents: content,
		Type:     b.tp,
	}
	if location.Path() != "" {
		lic.Locations = file.NewLocationSet(location)
	}
	return lic
}

func contentFromReader(r io.Reader) (string, error) {
	bytes, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytes)), nil
}

func sha256HexFromString(s string) string {
	hash := sha256.Sum256([]byte(s))
	return hex.EncodeToString(hash[:])
}
