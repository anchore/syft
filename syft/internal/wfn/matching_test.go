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

func TestHasWildcard(t *testing.T) {
	cases := []struct {
		Src    string
		Expect bool
	}{
		{"", false},
		{"foo", false},
		{"bar*", true},
		{"?baz", true},
		{`\\\\*foo`, true},
		{`bar\\\?`, false},
		{`foo\bar*`, true},
		{`b\?r?`, true},
	}
	for _, c := range cases {
		t.Run(c.Src, func(t *testing.T) {
			r := HasWildcard(c.Src)
			if r != c.Expect {
				t.Fatalf("HasWildcard(%q) returned %v, %v was expected", c.Src, r, c.Expect)
			}
		})
	}
}

func TestMatchStr(t *testing.T) {
	cases := []struct {
		Src    string
		Tgt    string
		Expect Relation
	}{
		{"foo", "bar", Disjoint},
		{"bar", "bar", Equal},
		{"*", "foo", Superset},
		{"*a?", "bar", Superset},
		{"*", "", Superset},
		{"f*", "foo", Superset},
		{"ba?", "bar", Superset},
		{"fo??", "foo", Disjoint},
		{"foo*", "foo", Superset},
		{"*bar", "bar", Superset},
		{"??o", "foo", Superset},
		{"??o", "bar", Disjoint},
		{"boo\\?", "boo\\?", Equal},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%q vs %q", c.Src, c.Tgt), func(t *testing.T) {
			r := matchStr(c.Src, c.Tgt)
			if r != c.Expect {
				t.Fatalf("matchStr returned %v, %v was expected", r, c.Expect)
			}
		})
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		Src    string
		Tgt    string
		Fail   bool
		Expect Relation
	}{
		{
			Src:    `cpe:2.3:a:microsoft:internet_explorer:8.*:sp?:*:*:*:*:*:*`,
			Tgt:    `cpe:2.3:a:microsoft:internet_explorer:8.0.6001:sp3:*:*:*:*:*:*`,
			Expect: Superset,
		},
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("%q vs %q", c.Src, c.Tgt), func(t *testing.T) {
			srcAttr, err := UnbindFmtString(c.Src)
			if err != nil {
				t.Fatalf("failed to unbind WFN from FSB %q: %v", c.Src, err)
			}
			tgtAttr, err := UnbindFmtString(c.Tgt)
			if err != nil {
				t.Fatalf("failed to unbind WFN from FSB %q: %v", c.Tgt, err)
			}
			r, err := Compare(srcAttr, tgtAttr)
			if c.Fail && err == nil {
				t.Fatal("test was expected to fail, but succeeded")
			}
			if !c.Fail && err != nil {
				t.Fatalf("test was expected to succeed, but failed: %v", err)
			}
			if r.Relation() != c.Expect {
				t.Fatalf("Compare returned %v (%v), %v was expected", r.Relation(), r, c.Expect)
			}
		})
	}
}

func BenchmarkCompare(b *testing.B) {
	src := `cpe:2.3:a:microsoft:*internet_ex??????:8.0.*:sp?:*:*:*:*:*:*`
	tgt := `cpe:2.3:a:microsoft:internet_explorer:8.1.6001:sp3:*:*:*:*:*:*`
	srcAttr, err := UnbindFmtString(src)
	if err != nil {
		b.Fatalf("failed to unbind WFN from FSB %q: %v", src, err)
	}
	tgtAttr, err := UnbindFmtString(tgt)
	if err != nil {
		b.Fatalf("failed to unbind WFN from FSB %q: %v", tgt, err)
	}
	for i := 0; i < b.N; i++ {
		// checking error and result adds about 10% of runtime to this benchmark on my machine
		// and correctness is covered by tests, so skip it
		Compare(srcAttr, tgtAttr)
	}
}

func BenchmarkMatch(b *testing.B) {
	src := `cpe:2.3:a:microsoft:*internet_ex??????:8.0.*:sp?:*:*:*:*:*:*`
	tgt := `cpe:2.3:a:microsoft:internet_explorer:8.1.6001:sp3:*:*:*:*:*:*`
	srcAttr, err := UnbindFmtString(src)
	if err != nil {
		b.Fatalf("failed to unbind WFN from FSB %q: %v", src, err)
	}
	tgtAttr, err := UnbindFmtString(tgt)
	if err != nil {
		b.Fatalf("failed to unbind WFN from FSB %q: %v", tgt, err)
	}
	for i := 0; i < b.N; i++ {
		// checking error and result adds about 10% of runtime to this benchmark on my machine
		// and correctness is covered by tests, so skip it
		Match(srcAttr, tgtAttr)
	}
}

func BenchmarkIsDisjoint(b *testing.B) {
	src := `cpe:2.3:a:microsoft:*internet_ex??????:8.*:sp?:*:*:*:*:*:1`
	tgt := `cpe:2.3:a:microsoft:internet_explorer:8.0.6001:sp3:*:*:*:*:*:2`
	srcAttr, err := UnbindFmtString(src)
	if err != nil {
		b.Fatalf("failed to unbind WFN from FSB %q: %v", src, err)
	}
	tgtAttr, err := UnbindFmtString(tgt)
	if err != nil {
		b.Fatalf("failed to unbind WFN from FSB %q: %v", tgt, err)
	}
	cmp, _ := Compare(srcAttr, tgtAttr)
	for i := 0; i < b.N; i++ {
		cmp.IsDisjoint()
	}
}

func BenchmarkHasWildcard(b *testing.B) {
	tests := map[string]string{
		"has":         `cpe:2.3:a:microsoft:*internet_ex??????:8.*:sp?:*:*:*:*:*:*`,
		"has not":     `cpe:2.3:a:microsoft:internet_explorer:8.0:sp2:*:*:*:*:*:*`,
		"has escaped": `cpe:2.3:a:vendor\?:product\?:8.0:sp2:*:*:*:*:*:*`,
	}
	for tag, test := range tests {
		b.Run(tag, func(b *testing.B) {
			srcAttr, err := UnbindFmtString(test)
			if err != nil {
				b.Fatalf("failed to unbind WFN from FSB %q: %v", test, err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				HasWildcard(srcAttr.Vendor)
				HasWildcard(srcAttr.Product)
			}
		})
	}
}
