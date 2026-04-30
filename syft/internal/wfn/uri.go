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
	"strconv"
	"strings"
)

// BindToURI binds WFN to URI
func (a Attributes) BindToURI() string {
	var parts []string
	for i, v := range []string{
		a.Part,
		a.Vendor,
		a.Product,
		a.Version,
		a.Update,
		"",
		a.Language,
	} {
		if i != 5 { // other than edition
			parts = append(parts, bindValueURI(v))
			continue
		}
		edParts := make([]string, 5)
		allNAs := true
		for i, v2 := range []string{a.Edition, a.SWEdition, a.TargetSW, a.TargetHW, a.Other} {
			edParts[i] = bindValueURI(v2)
			if edParts[i] != "-" {
				allNAs = false
			}
		}
		if allNAs {
			parts = append(parts, "-")
		} else {
			parts = append(parts, pack(edParts))
		}
	}
	// empty elements at the end of the URI should be omitted
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" {
			break
		}
		parts = parts[:i]
	}
	return uriPrefix + strings.Join(parts, ":")
}

// UnbindURI loads WFN from URI
func UnbindURI(s string) (*Attributes, error) {
	if !strings.HasPrefix(s, uriPrefix) {
		return nil, fmt.Errorf("unbind uri: bad prefix in URI %q", s)
	}
	s = strings.ToLower(s[len(uriPrefix):]) // reject schema prefix + normalize
	attr := Attributes{}
	var err error
	for i, partN := 0, 0; i < len(s); i, partN = i+1, partN+1 {
		switch partN {
		case 0:
			attr.Part, i, err = unbindValueURIAtTill(s, i, ':')
		case 1:
			attr.Vendor, i, err = unbindValueURIAtTill(s, i, ':')
		case 2:
			attr.Product, i, err = unbindValueURIAtTill(s, i, ':')
		case 3:
			attr.Version, i, err = unbindValueURIAtTill(s, i, ':')
		case 4:
			attr.Update, i, err = unbindValueURIAtTill(s, i, ':')
		case 5:
			if s[i] != '~' {
				attr.Edition, i, err = unbindValueURIAtTill(s, i, ':')
				break
			}
			i++
		edition23:
			for subpartN := 0; i < len(s); i, subpartN = i+1, subpartN+1 {
				switch subpartN {
				case 0:
					attr.Edition, i, err = unbindValueURIAtTill(s, i, '~')
				case 1:
					attr.SWEdition, i, err = unbindValueURIAtTill(s, i, '~')
				case 2:
					attr.TargetSW, i, err = unbindValueURIAtTill(s, i, '~')
				case 3:
					attr.TargetHW, i, err = unbindValueURIAtTill(s, i, '~')
				case 4:
					attr.Other, i, err = unbindValueURIAtTill(s, i, ':')
				default:
					break edition23
				}
			}
		case 6:
			attr.Language, i, err = unbindValueURIAtTill(s, i, ':')
		}
		if err != nil {
			return nil, fmt.Errorf("unbind uri: %v", err)
		}
	}
	return &attr, nil
}

func pack(ss []string) string {
	compat := true
	for _, s := range ss[1:] {
		if s != "" {
			compat = false
			break
		}
	}
	if compat {
		return ss[0]
	}
	return "~" + strings.Join(ss, "~")
}

// Scans an input string s and applies the following transformations:
// - pass alphanumeric characters thru untouched
// - percent-encode quoted non-alphanumerics as needed
// - unquoted special characters are mapped to their special forms.
func bindValueURI(s string) string {
	var out []byte
	switch s {
	case NA:
		return "-"
	case Any:
		return ""
	}
	for i := 0; i < len(s); i++ {
		b := byte(s[i])
		if b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b == '_' {
			// alnum + '_' pass untouched
			out = append(out, b)
		} else if b == '\\' {
			// percent-encode escaped characters
			// sanity check should be done during unbinding, so here we silently skip all
			// illegal characters
			i++
			if i == len(s) {
				break
			}
			out = append(out, pctEncode(s[i])...)
		} else if b == '?' { // unquoted '?' -> "%01"
			out = append(out, '%', '0', '1')
		} else if b == '*' { // unquoted '*' -> "%02"
			out = append(out, '%', '0', '2')
		}
	}
	return string(out)
}

func unbindValueURIAtTill(s string, at int, till byte) (string, int, error) {
	if at >= len(s) || s[at] == till {
		return Any, at, nil
	}
	if s[at] == '-' {
		return NA, at + 1, nil
	}
	out := make([]byte, 0, len(s)*2) // assume the worst
	embedded := false
	i := at
loop:
	for ; i < len(s); i++ {
		switch s[i] {
		case till:
			break loop
		case '%':
			if i+3 > len(s) {
				return "", i, fmt.Errorf("unbind URI attribute: illegal percent-encoded value at %d: %q", i, s[i:])
			}
			codeStr := string(s[i : i+3])
			code, err := strconv.ParseInt(string(s[i+1:i+3]), 16, 8)
			if err != nil {
				return "", i, fmt.Errorf("unbind URI attribute: illegal percent-encoded value at %d: %q", i, s[i+1:i+3])
			}
			if code == 0x1 || code == 0x2 {
				if !(i == at || i == len(s)-3 || s[i+3] == till || // at the beginning or at the end of the string
					(!embedded && i > 2 && s[i-3:i] == codeStr || // not embedded and preceded by the same symbol
						(embedded && i+6 < len(s) && s[i+3:i+6] == codeStr))) { // embedded and followed by the same symbol
					return "", i, fmt.Errorf("unbind URI attribute: %%%02d is embedded into string %q", code, s)
				}
				switch code {
				case 0x1:
					out = append(out, '?')
				case 0x2:
					out = append(out, '*')
				}
				i += 2
				break
			}
			switch code {
			case 0x21:
				out = append(out, '\\', '!')
			case 0x22:
				out = append(out, '\\', '"')
			case 0x23:
				out = append(out, '\\', '#')
			case 0x24:
				out = append(out, '\\', '$')
			case 0x25:
				out = append(out, '\\', '%')
			case 0x26:
				out = append(out, '\\', '&')
			case 0x27:
				out = append(out, '\\', '\'')
			case 0x28:
				out = append(out, '\\', '(')
			case 0x29:
				out = append(out, '\\', ')')
			case 0x2a:
				out = append(out, '\\', '*')
			case 0x2b:
				out = append(out, '\\', '+')
			case 0x2c:
				out = append(out, '\\', ',')
			case 0x2f:
				out = append(out, '\\', '/')
			case 0x3a:
				out = append(out, '\\', ':')
			case 0x3b:
				out = append(out, '\\', ';')
			case 0x3c:
				out = append(out, '\\', '<')
			case 0x3d:
				out = append(out, '\\', '=')
			case 0x3e:
				out = append(out, '\\', '>')
			case 0x3f:
				out = append(out, '\\', '?')
			case 0x40:
				out = append(out, '\\', '@')
			case 0x5b:
				out = append(out, '\\', '[')
			case 0x5c:
				out = append(out, '\\', '\\')
			case 0x5d:
				out = append(out, '\\', ']')
			case 0x5e:
				out = append(out, '\\', '^')
			case 0x60:
				out = append(out, '\\', '`')
			case 0x7b:
				out = append(out, '\\', '{')
			case 0x7c:
				out = append(out, '\\', '|')
			case 0x7d:
				out = append(out, '\\', '}')
			case 0x7e:
				out = append(out, '\\', '~')
			default:
				return "", i, fmt.Errorf("unbind URI attribute: illegal percent-encoded value %q", s[i+1:i+3])
			}
			i += 2
			embedded = true
		case '.', '-', '~':
			out = append(out, '\\', s[i])
			embedded = true
		default:
			out = append(out, s[i])
			embedded = true
		}
	}
	return string(out), i, nil
}

func pctEncode(b byte) []byte {
	switch b {
	case '!':
		return []byte("%21")
	case '"':
		return []byte("%22")
	case '#':
		return []byte("%23")
	case '$':
		return []byte("%24")
	case '%':
		return []byte("%25")
	case '&':
		return []byte("%26")
	case '\'':
		return []byte("%27")
	case '(':
		return []byte("%28")
	case ')':
		return []byte("%29")
	case '*':
		return []byte("%2a")
	case '+':
		return []byte("%2b")
	case ',':
		return []byte("%2c")
	case '-':
		return []byte("-") // bound without encoding
	case '.':
		return []byte(".") // bound without encoding
	case '/':
		return []byte("%2f")
	case ':':
		return []byte("%3a")
	case ';':
		return []byte("%3b")
	case '<':
		return []byte("%3c")
	case '=':
		return []byte("%3d")
	case '>':
		return []byte("%3e")
	case '?':
		return []byte("%3f")
	case '@':
		return []byte("%40")
	case '[':
		return []byte("%5b")
	case '\\':
		return []byte("%5c")
	case ']':
		return []byte("%5d")
	case '^':
		return []byte("%5e")
	case '`':
		return []byte("%60")
	case '{':
		return []byte("%7b")
	case '|':
		return []byte("%7c")
	case '}':
		return []byte("%7d")
	case '~':
		return []byte("%7e")
	default:
		return []byte{b}
	}
}
