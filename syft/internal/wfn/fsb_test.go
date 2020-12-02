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

func TestUnbindFmtString(t *testing.T) {
	cases := []struct {
		FSB    string
		Expect string
		Fail   bool
	}{
		{
			FSB:    "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*",
			Expect: `wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.0\.6001",update="beta",edition=ANY,language=ANY]`,
		},
		{
			FSB:    "cpe:2.3:a:microsoft:internet_exp?????:8.*:sp?:*:*:*:*:*:*",
			Expect: `wfn:[part="a",vendor="microsoft",product="internet_exp?????",version="8\.*",update="sp?",edition=ANY,language=ANY]`,
		},
		{
			FSB:    "cpe:2.3:a:microsoft:internet_explorer:8.*:sp?:*:*:*:*:*:*",
			Expect: `wfn:[part="a",vendor="microsoft",product="internet_explorer",version="8\.*",update="sp?",edition=ANY,language=ANY]`,
		},
		{
			FSB:    "cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:-:*:*:online:win2003:x64:*",
			Expect: `wfn:[part="a",vendor="hp",product="insight_diagnostics",version="7\.4\.0\.1570",update=NA,edition=ANY,sw_edition="online",target_sw="win2003",target_hw="x64",other=ANY,language=ANY]`,
		},
		{
			FSB:    `cpe:2.3:a:foo\\bar:big\$money:2010:*:*:*:special:ipod_touch:80gb:*`,
			Expect: `wfn:[part="a",vendor="foo\\bar",product="big\$money",version="2010",update=ANY,edition=ANY,sw_edition="special",target_sw="ipod_touch",target_hw="80gb",other=ANY,language=ANY]`,
		},
		{
			FSB:  `cpe:2.3:a:cisco:cisco_security_monitoring\`,
			Fail: true,
		},
		{
			FSB:  `cpe:2.3:a:disney:where\\'s_my_perry?_free:1.5.1:*:*:*:*:android:*:*`,
			Fail: true,
		},
		{
			FSB:  "cpe:2.3:a:hp:insight_diagnostics:7.4.*.1570:*:*:*:*:*:*",
			Fail: true,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.FSB, func(t *testing.T) {
			attr, err := UnbindFmtString(tc.FSB)
			if err != nil {
				if tc.Fail {
					return
				}
				t.Fatalf("failed to parse FSB %q: %v", tc.FSB, err)
			}
			if tc.Fail {
				t.Fatalf("FSB parsed successfully, despite failure was expected: %q", tc.FSB)
			}
			if attr.String() != tc.Expect {
				t.Fatalf("expected %s\ngot %s", tc.Expect, attr)
			}
		})
	}
}

func BenchmarkUnbindFmtString(t *testing.B) {
	for i := 0; i < t.N; i++ {
		UnbindFmtString("cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:-:*:*:online:win2003:x64:*")
	}
}

func TestBindToFmtString(t *testing.T) {
	cases := []string{
		"cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*",
		"cpe:2.3:a:microsoft:internet_explorer:8.*:sp?:*:*:*:*:*:*",
		"cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:-:*:*:online:win2003:x64:*",
		`cpe:2.3:a:foo\\bar:big\$\*\?money:2010:*:*:*:special:ipod_touch:80gb:*`,
	}
	for n, c := range cases {
		c := c
		t.Run(fmt.Sprintf("case#%d", n), func(t *testing.T) {
			attr, err := UnbindFmtString(c)
			if err != nil {
				t.Fatalf("failed to parse test input %q: %v", c, err)
			}
			if out := attr.BindToFmtString(); out != c {
				t.Fatalf("expected %s\ngot %s", c, out)
			}
		})
	}
}
