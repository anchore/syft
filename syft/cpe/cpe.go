package cpe

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
)

type CPE = wfn.Attributes

const (
	allowedCPEPunctuation = "-!\"#$%&'()+,./:;<=>@[]^`{|}~"
)

// This regex string is taken from
// https://csrc.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd which has the official cpe spec
// This first part matches CPE urls and the second part matches binding strings
const cpeRegexString = ((`^([c][pP][eE]:/[AHOaho]?(:[A-Za-z0-9\._\-~%]*){0,6})`) +
	// Or match the CPE binding string
	// Note that we had to replace '`' with '\x60' to escape the backticks
	`|(cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^\x60\{\|}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^\x60\{\|}~]))+(\?*|\*?))|[\*\-])){4})$`)

var cpeRegex = regexp.MustCompile(cpeRegexString)

// New will parse a formatted CPE string and return a CPE object. Some input, such as the existence of whitespace
// characters is allowed, however, a more strict validation is done after this sanitization process.
func New(cpeStr string) (CPE, error) {
	// get a CPE object based on the given string --don't validate yet since it may be possible to escape select cases on the callers behalf
	c, err := newWithoutValidation(cpeStr)
	if err != nil {
		return CPE{}, fmt.Errorf("unable to parse CPE string: %w", err)
	}

	// ensure that this CPE can be validated after being fully sanitized
	if ValidateString(String(c)) != nil {
		return CPE{}, err
	}

	// we don't return the sanitized string, as this is a concern for later when creating CPE strings. In fact, since
	// sanitization is lossy (whitespace is replaced, not escaped) it's important that the raw values are left as.
	return c, nil
}

// Must returns a CPE or panics if the provided string is not valid
func Must(cpeStr string) CPE {
	c, err := New(cpeStr)
	if err != nil {
		panic(err)
	}
	return c
}

func ValidateString(cpeStr string) error {
	// We should filter out all CPEs that do not match the official CPE regex
	// The facebook nvdtools parser can sometimes incorrectly parse invalid CPE strings
	if !cpeRegex.MatchString(cpeStr) {
		return fmt.Errorf("failed to parse CPE=%q as it doesn't match the regex=%s", cpeStr, cpeRegexString)
	}
	return nil
}

func newWithoutValidation(cpeStr string) (CPE, error) {
	value, err := wfn.Parse(cpeStr)
	if err != nil {
		return CPE{}, fmt.Errorf("failed to parse CPE=%q: %w", cpeStr, err)
	}

	if value == nil {
		return CPE{}, fmt.Errorf("failed to parse CPE=%q", cpeStr)
	}

	// we need to compare the raw data since we are constructing CPEs in other locations
	value.Vendor = normalizeField(value.Vendor)
	value.Product = normalizeField(value.Product)
	value.Language = normalizeField(value.Language)
	value.Version = normalizeField(value.Version)
	value.TargetSW = normalizeField(value.TargetSW)
	value.Part = normalizeField(value.Part)
	value.Edition = normalizeField(value.Edition)
	value.Other = normalizeField(value.Other)
	value.SWEdition = normalizeField(value.SWEdition)
	value.TargetHW = normalizeField(value.TargetHW)
	value.Update = normalizeField(value.Update)

	return *value, nil
}

func normalizeField(field string) string {
	// replace spaces with underscores (per section 5.3.2 of the CPE spec v 2.3)
	field = strings.ReplaceAll(field, " ", "_")

	// keep dashes and forward slashes unescaped
	if field == "*" {
		return wfn.Any
	}
	return stripSlashes(field)
}

// stripSlashes is a reverse of the sanitize function below.
// It correctly removes slashes that are followed by allowed puncts.
// This is to allow for a correct round trip parsing of cpes with quoted characters.
func stripSlashes(s string) string {
	sb := strings.Builder{}
	for i, c := range s {
		if c == '\\' && i+1 < len(s) && strings.ContainsRune(allowedCPEPunctuation, rune(s[i+1])) {
			continue
		}
		sb.WriteRune(c)
	}
	return sb.String()
}

func String(c CPE) string {
	output := CPE{}
	output.Vendor = sanitize(c.Vendor)
	output.Product = sanitize(c.Product)
	output.Language = sanitize(c.Language)
	output.Version = sanitize(c.Version)
	output.TargetSW = sanitize(c.TargetSW)
	output.Part = sanitize(c.Part)
	output.Edition = sanitize(c.Edition)
	output.Other = sanitize(c.Other)
	output.SWEdition = sanitize(c.SWEdition)
	output.TargetHW = sanitize(c.TargetHW)
	output.Update = sanitize(c.Update)
	return output.BindToFmtString()
}

// sanitize is a modified version of WFNize function from nvdtools
// that quotes all the allowed punctation chars with a slash and replaces
// spaces with underscores. It differs from the upstream implmentation as
// it does not use the buggy nvdtools implementation, specifically the "addSlashesAt" part of the
// function which stops the loop as soon as it encounters ":" a valid
// character for a WFN attribute after quoting, but the way nvdtools
// handles it causes it to truncate strings that container ":". As a result
// strings like "prefix:1.2" which would have been quoted as "prefix\:1.2"
// end up becoming "prefix" instead causing loss of information and
// incorrect CPEs being generated.
func sanitize(s string) string {
	// replace spaces with underscores
	in := strings.ReplaceAll(s, " ", "_")

	// escape allowable punctuation per section 5.3.2 in the CPE 2.3 spec
	sb := strings.Builder{}
	for _, c := range in {
		if strings.ContainsRune(allowedCPEPunctuation, c) {
			sb.WriteRune('\\')
		}
		sb.WriteRune(c)
	}
	return sb.String()
}
