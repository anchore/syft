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
	"unicode"
)

// BindToFmtString binds WFN to formatted string
func (a Attributes) BindToFmtString() string {
	parts := make([]string, 11)
	for i, s := range []string{
		a.Part,
		a.Vendor,
		a.Product,
		a.Version,
		a.Update,
		a.Edition,
		a.Language,
		a.SWEdition,
		a.TargetSW,
		a.TargetHW,
		a.Other,
	} {
		parts[i] = bindValueFS(s)
	}
	return fsbPrefix + strings.Join(parts, ":")
}

// UnbindFmtString loads WFN from formatted string
func UnbindFmtString(s string) (*Attributes, error) {
	if !strings.HasPrefix(s, fsbPrefix) {
		return nil, fmt.Errorf("bad prefix in FSB %q", s)
	}
	attr := &Attributes{}
	for i, partN := len(fsbPrefix), 0; i < len(s); i, partN = i+1, partN+1 {
		var err error
		switch partN {
		case 0:
			attr.Part, i, err = unbindValueFSAt(s, i)
		case 1:
			attr.Vendor, i, err = unbindValueFSAt(s, i)
		case 2:
			attr.Product, i, err = unbindValueFSAt(s, i)
		case 3:
			attr.Version, i, err = unbindValueFSAt(s, i)
		case 4:
			attr.Update, i, err = unbindValueFSAt(s, i)
		case 5:
			attr.Edition, i, err = unbindValueFSAt(s, i)
		case 6:
			attr.Language, i, err = unbindValueFSAt(s, i)
		case 7:
			attr.SWEdition, i, err = unbindValueFSAt(s, i)
		case 8:
			attr.TargetSW, i, err = unbindValueFSAt(s, i)
		case 9:
			attr.TargetHW, i, err = unbindValueFSAt(s, i)
		case 10:
			attr.Other, i, err = unbindValueFSAt(s, i)
		}
		if err != nil {
			return nil, fmt.Errorf("unbind formatted string: %v", err)
		}
	}
	return attr, nil
}

// StripSlashes removes escaping of punctuation characters from attribute value
func StripSlashes(s string) string {
	out := make([]byte, 0, len(s)) // might be more than we need, but no reallocs
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i < len(s)-1 {
			switch s[i+1] {
			case '.', '_', '-': // these pass unquoted
				continue
			}
		}
		out = append(out, byte(s[i]))
	}
	return string(out)
}

func bindValueFS(s string) string {
	switch s {
	case Any:
		return "*"
	case NA:
		return "-"
	default:
		return StripSlashes(s)
	}
}

func unbindValueFSAt(s string, at int) (string, int, error) {
	if len(s)-at < 1 || s[at] == ':' {
		return Any, at, fmt.Errorf("could not unbind attribute at pos %d", at)
	}
	if len(s)-at == 1 || s[at+1] == ':' {
		switch s[at] {
		case '*':
			return Any, at + 1, nil
		case '-':
			return NA, at + 1, nil
		default:
			return s[at : at+1], at + 1, nil
		}
	}
	return addSlashesAt(s, at)
}

func addSlashesAt(s string, at int) (string, int, error) {
	b := make([]byte, 0, len(s)*2) // assume a quote for every character
	embedded := false
	i := at
	for ; i < len(s) && s[i] != ':'; i++ {
		c := s[i]
		if unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)) || c == '_' {
			b = append(b, c)
			embedded = true
			continue
		}
		switch c {
		case '\\':
			i++
			if i == len(s) {
				return "", i, fmt.Errorf("unquoted '\\' at the end of the FSB fragment: %q", s)
			}
			b = append(b, c, s[i])
			embedded = true
		case '*':
			// An unquoted asterisk must appear at the beginning or end of the string
			if i != at && i != len(s)-1 && s[i+1] != ':' {
				return Any, i, fmt.Errorf("unquoted '*' inside the FSB fragment: %q", s)
			}
			b = append(b, c)
			embedded = true
		case '?':
			if !(i == at || i == len(s)-1 || s[i+1] == ':' || // at the beginning or at the end of the string
				(!embedded && i > 0 && s[i-1] == c || // not embedded and preceded by the same symbol
					(embedded && s[i+1] == c))) { // embedded and followed by the same symbol
				return Any, i, fmt.Errorf("unquoted '?' inside the FSB fragment %q (%t, %d)", s, embedded, i)
			}
			b = append(b, c)
			embedded = false
		default:
			b = append(b, '\\', c)
			embedded = true
		}
	}
	return string(append([]byte{}, b...)), i, nil
}
