//go:build go1.18
// +build go1.18

// Copyright 2026 Anchore, Inc.
// SPDX-License-Identifier: Apache-2.0

package syft_test

import (
	"testing"

	"github.com/anchore/syft/syft/cpe"
)

// FuzzCPEParse tests CPE (Common Platform Enumeration) parsing
// with arbitrary attacker-controlled CPE strings.
//
// CPE is the standard identifier format for vulnerable software.
// Syft generates CPEs from untrusted package data.
func FuzzCPEParse(f *testing.F) {
	f.Add("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	f.Add("cpe:/a:vendor:product:1.0")
	f.Add("")
	f.Add("invalid-cpe")
	f.Add(string(make([]byte, 1000)))

	f.Fuzz(func(t *testing.T, cpeStr string) {
		if len(cpeStr) > 1<<16 {
			return
		}
		_, _ = cpe.New(cpeStr, cpe.DeclaredSource)
	})
}

// FuzzCPEBind tests CPE string binding with arbitrary
// CPE 2.3 formatted strings.
func FuzzCPEBind(f *testing.F) {
	f.Add("cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*")
	f.Add("")
	f.Add(string(make([]byte, 1000)))

	f.Fuzz(func(t *testing.T, cpeStr string) {
		if len(cpeStr) > 1<<16 {
			return
		}
		_, _ = cpe.New(cpeStr, cpe.DeclaredSource)
	})
}
