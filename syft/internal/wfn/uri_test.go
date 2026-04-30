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
	"testing"
)

func TestUnbindURI(t *testing.T) {
	cases := []struct {
		URI    string
		Expect string
		Fail   bool
	}{
		{
			URI:    "cpe:/a",
			Expect: `wfn:[part="a",vendor=ANY,product=ANY,version=ANY,update=ANY,edition=ANY,language=ANY]`,
		},
		{
			URI:    "cpe:/a:microsoft:internet_explorer:8.0.6001:beta",
			Expect: `wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.0\.6001",update="beta",edition=ANY,language=ANY]`,
		},
		{
			URI:    "cpe:/a:microsoft:internet_explorer:8.%2a:sp%3f",
			Expect: `wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.\*",update="sp\?",edition=ANY,language=ANY]`,
		},
		{
			URI:    "cpe:/a:microsoft:internet_explorer:8.%02:sp%01",
			Expect: `wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.*",update="sp?",edition=ANY,language=ANY]`,
		},
		{
			URI:    "cpe:/a:Microsoft:internet_explorer:8.%02:sp%01:limited",
			Expect: `wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.*",update="sp?",edition="limited",language=ANY]`,
		},
		{
			URI:    "cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~",
			Expect: `wfn:[part="a",vendor="hp",product="insight_diagnostics",version="7\.4\.0\.1570",update=ANY,edition=ANY,sw_edition="online",target_sw="win2003",target_hw="x64",other=ANY,language=ANY]`,
		},
		{
			URI:    "cpe:/o:microsoft:windows_10:-::~~~~x64~",
			Expect: `wfn:[part="o",vendor="microsoft",product="windows_10",version=NA,update=ANY,edition=ANY,sw_edition=ANY,target_sw=ANY,target_hw="x64",other=ANY,language=ANY]`,
		},
		{
			URI:  `cpe:/a:foo:boo%02%02`,
			Fail: true,
		},
		{
			URI:  "cpe:/a:foo:bar:12.%02.1234",
			Fail: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.URI, func(t *testing.T) {
			attr, err := UnbindURI(tc.URI)
			if err != nil {
				if tc.Fail {
					return
				}
				t.Fatalf("failed to parse URI %q: %v", tc.URI, err)
			}
			if tc.Fail {
				t.Fatalf("URI parsed successfully, despite failure was expected: %q", tc.URI)
			}
			if attr.String() != tc.Expect {
				t.Fatalf("expected %s\ngot %s", tc.Expect, attr)
			}
		})
	}
}

func BenchmarkUnbindURI(t *testing.B) {
	for i := 0; i < t.N; i++ {
		UnbindURI("cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~")
	}
}

func TestBindToURI(t *testing.T) {
	cases := []string{
		"cpe:/a:microsoft:internet_explorer:8.0.6001:beta",
		"cpe:/a:microsoft:internet_explorer:8.%2a:sp%3f",
		"cpe:/a:microsoft:internet_explorer:8.%02:sp%01",
		"cpe:/a:microsoft:internet_explorer:8.%02:sp%01:limited",
		"cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~",
	}
	for n, c := range cases {
		c := c
		t.Run(fmt.Sprintf("case#%d", n), func(t *testing.T) {
			attr, err := UnbindURI(c)
			if err != nil {
				t.Fatalf("failed to parse input %q: %v", c, err)
			}
			if out := attr.BindToURI(); out != c {
				t.Fatalf("expected %s\ngot %s", c, out)
			}
		})
	}
}
