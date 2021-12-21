package pkg

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/facebookincubator/nvdtools/wfn"
)

type CPE = wfn.Attributes

// This regex string is taken from
// https://csrc.nist.gov/schema/cpe/2.3/cpe-naming_2.3.xsd which has the official cpe spec
// This first part matches CPE urls and the second part matches binding strings
const cpeRegexString = ((`([c][pP][eE]:/[AHOaho]?(:[A-Za-z0-9\._\-~%]*){0,6})`) +
	// Or match the CPE binding string
	// Note that we had to replace '`' with '\x60' to escape the backticks
	`|(cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^\x60\{\|}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!"#$$%&'\(\)\+,/:;<=>@\[\]\^\x60\{\|}~]))+(\?*|\*?))|[\*\-])){4})`)

var cpeRegex = regexp.MustCompile(cpeRegexString)

func NewCPE(cpeStr string) (CPE, error) {
	// We should filter out all CPEs that do not match the official CPE regex
	// The facebook nvdtools parser can sometimes incorrectly parse invalid CPE strings
	if !cpeRegex.Match([]byte(cpeStr)) {
		return CPE{}, fmt.Errorf("failed to parse CPE=%q as it doesn't match the regex=%s", cpeStr, cpeRegexString)
	}
	value, err := wfn.Parse(cpeStr)
	if err != nil {
		return CPE{}, fmt.Errorf("failed to parse CPE=%q: %w", cpeStr, err)
	}

	if value == nil {
		return CPE{}, fmt.Errorf("failed to parse CPE=%q", cpeStr)
	}

	// we need to compare the raw data since we are constructing CPEs in other locations
	value.Vendor = normalizeCpeField(value.Vendor)
	value.Product = normalizeCpeField(value.Product)
	value.Language = normalizeCpeField(value.Language)
	value.Version = normalizeCpeField(value.Version)
	value.TargetSW = normalizeCpeField(value.TargetSW)
	value.Part = normalizeCpeField(value.Part)
	value.Edition = normalizeCpeField(value.Edition)
	value.Other = normalizeCpeField(value.Other)
	value.SWEdition = normalizeCpeField(value.SWEdition)
	value.TargetHW = normalizeCpeField(value.TargetHW)
	value.Update = normalizeCpeField(value.Update)

	return *value, nil
}

func MustCPE(cpeStr string) CPE {
	c, err := NewCPE(cpeStr)
	if err != nil {
		panic(err)
	}
	return c
}

func normalizeCpeField(field string) string {
	// keep dashes and forward slashes unescaped
	if field == "*" {
		return wfn.Any
	}
	return strings.ReplaceAll(wfn.StripSlashes(field), `\/`, "/")
}
