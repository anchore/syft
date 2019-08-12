// Copyright (c) Facebook, Inc. and its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wfn

import (
	"fmt"
	"strings"
)

// KnownParts is a map of known WFN attribute parts.
var KnownParts = map[string]string{
	"a": "application",
	"o": "operating system",
	"h": "hardware",
}

// Possible logical value of Attributes
// empty string considered ANY when parsing and unquoted "-" is illegal in WFN attribute-value
const (
	Any = ""
	NA  = "-"
)

const (
	uriPrefix = "cpe:/"
	fsbPrefix = "cpe:2.3:"
)

var parsers = map[string]func(s string) (*Attributes, error){
	uriPrefix: UnbindURI,
	fsbPrefix: UnbindFmtString,
}

// Parse parses Attributes from URI or formatted string binding.
func Parse(s string) (*Attributes, error) {
	for prefix, parserFunc := range parsers {
		if strings.HasPrefix(s, prefix) {
			return parserFunc(s)
		}
	}
	return nil, fmt.Errorf("wfn: unsupported format %q", s)
}

// Attributes defines the WFN Data Model Attributes.
type Attributes struct {
	Part      string
	Vendor    string
	Product   string
	Version   string
	Update    string
	Edition   string
	SWEdition string
	TargetSW  string
	TargetHW  string
	Other     string
	Language  string
}

// NewAttributesWithNA allocates Attributes object with all fields initialized to NA logical value
func NewAttributesWithNA() *Attributes {
	return newAttributes(NA)
}

// NewAttributesWithAny allocates Attributes object with all fields initialized to Any logical value
func NewAttributesWithAny() *Attributes {
	return newAttributes(Any)
}

func newAttributes(defaultValue string) *Attributes {
	return &Attributes{
		Part:      defaultValue,
		Vendor:    defaultValue,
		Product:   defaultValue,
		Version:   defaultValue,
		Update:    defaultValue,
		Edition:   defaultValue,
		SWEdition: defaultValue,
		TargetSW:  defaultValue,
		TargetHW:  defaultValue,
		Other:     defaultValue,
		Language:  defaultValue,
	}
}

// WFNize transforms a string into CPE23-NAME compliant avstring value.
// This function isn't a part of standard. Quoted wildcards (*?) become unquoted ones (i.e. act as wildcards,
// not a literal '*' and '?')
// If wildcards are used, it is a responsibility of the user to make sure they comply with the standard, i.e.
// only appear at the beginning or at the end of the string and, in case of asterisk, only once in each case.
// Uppercase letters are valid avstring characters, but they are rarely (if ever) used in WFNs. It is recommended
// to strings.ToLower() the string before passing it to this function.
func WFNize(s string) (string, error) {
	const allowedPunct = "-!\"#$%&'()+,./:;<=>@[]^`{|}!~"
	// replace spaces with underscores
	in := strings.Replace(s, " ", "_", -1)
	buf := make([]byte, 0, len(in))
	// remove illegal characters
	for n, c := range in {
		c := byte(c)
		if c >= 'A' && c <= 'Z' ||
			c >= 'a' && c <= 'z' ||
			c >= '0' && c <= '9' ||
			c == '_' ||
			strings.IndexByte(allowedPunct, c) != -1 {
			buf = append(buf, c)
		}
		// handle wildcard characters
		if c == '*' || c == '?' {
			if n == 0 || in[n-1] != '\\' {
				buf = append(buf, '\\')
			}
			buf = append(buf, c)
		}
	}
	// quote everything that requires quoting
	s, _, err := addSlashesAt(string(buf), 0)
	return s, err
}

// String returns a string representation of the wfn
func (a Attributes) String() string {
	parts := make([]string, 0, 11)
	// these are always displayed
	parts = append(parts, keyValueString("part", a.Part))
	parts = append(parts, keyValueString("vendor", a.Vendor))
	parts = append(parts, keyValueString("product", a.Product))
	parts = append(parts, keyValueString("version", a.Version))
	parts = append(parts, keyValueString("update", a.Update))
	parts = append(parts, keyValueString("edition", a.Edition))
	// these are present only if one of them isn't ANY (cpe:2.2 compartibility)
	if a.SWEdition != Any || a.TargetHW != Any || a.TargetSW != Any || a.Other != Any {
		parts = append(parts, keyValueString("sw_edition", a.SWEdition))
		parts = append(parts, keyValueString("target_sw", a.TargetSW))
		parts = append(parts, keyValueString("target_hw", a.TargetHW))
		parts = append(parts, keyValueString("other", a.Other))
	}
	// also always displayed
	parts = append(parts, keyValueString("language", a.Language))
	return fmt.Sprintf("wfn:[%s]", strings.Join(parts, ","))
}

func keyValueString(k, v string) string {
	switch v {
	case Any:
		return fmt.Sprintf("%s=ANY", k)
	case NA:
		return fmt.Sprintf("%s=NA", k)
	default:
		return fmt.Sprintf("%s=\"%s\"", k, v)
	}
}
