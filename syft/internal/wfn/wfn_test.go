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

import "testing"

func TestWFNize(t *testing.T) {
	cases := []struct {
		in        string
		expected  string
		expectErr bool
	}{
		{"Zonealarm Wireless Security", "Zonealarm_Wireless_Security", false},
		{"1.8.14.6001", `1\.8\.14\.6001`, false},
		{"xorg-server", `xorg\-server`, false},
		{`1.8.\*`, `1\.8\.*`, false},
		{"1.*.14", `1\.\*\.14`, false},
		{`1.\*.14`, "", true},
	}
	for _, c := range cases {
		res, err := WFNize(c.in)
		if err != nil {
			if !c.expectErr {
				t.Errorf("WFNize(%q) returned error: %v", c.in, err)
			}
		} else if c.expectErr {
			t.Errorf("WFNize(%q) was expected to fail, but succedeed", c.in)
		} else if res != c.expected {
			t.Errorf("WFNize(%q) returned %q, %q was expected", c.in, res, c.expected)
		}
	}
}

func BenchmarkWFNize(t *testing.B) {
	for i := 0; i < t.N; i++ {
		WFNize("1.8.14.6001")
	}
}
