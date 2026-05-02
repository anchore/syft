package vscode

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseExtensionsJSON(t *testing.T) {
	fixture := "testdata/extensions/.vscode/extensions/extensions.json"
	locations := file.NewLocationSet(file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	expected := []pkg.Package{
		{
			Name:      "anthropic.claude-code",
			Version:   "2.1.114",
			Type:      pkg.VscodeExtensionPkg,
			PURL:      "pkg:vscode-extension/anthropic/claude-code@2.1.114",
			Locations: locations,
			Metadata: pkg.VscodeExtensionEntry{
				Publisher:            "anthropic",
				PublisherDisplayName: "Anthropic",
				UUID:                 "4c8b3c91-9d63-4c8e-a512-b5d6e3a2c1f0",
				IsPreReleaseVersion:  true,
			},
		},
		{
			Name:      "github.copilot-chat",
			Version:   "0.44.1",
			Type:      pkg.VscodeExtensionPkg,
			PURL:      "pkg:vscode-extension/github/copilot-chat@0.44.1",
			Locations: locations,
			Metadata: pkg.VscodeExtensionEntry{
				Publisher:            "github",
				PublisherDisplayName: "GitHub",
				UUID:                 "7ec7d6e6-b89e-4cc5-a59b-d6c4d238246f",
				IsBuiltin:            true,
			},
		},
		{
			// extension id with multiple dots — only the first dot delimits
			// publisher from name, so the canonical name is "cpptools-extension-pack".
			Name:      "ms-vscode.cpptools-extension-pack",
			Version:   "1.3.1",
			Type:      pkg.VscodeExtensionPkg,
			PURL:      "pkg:vscode-extension/ms-vscode/cpptools-extension-pack@1.3.1",
			Locations: locations,
			Metadata: pkg.VscodeExtensionEntry{
				Publisher:            "ms-vscode",
				PublisherDisplayName: "Microsoft",
				UUID:                 "53b5e9a8-77c1-44a8-91ee-69ace8ef1c4d",
				TargetPlatform:       "linux-x64",
			},
		},
	}

	pkgtest.TestFileParser(t, fixture, parseExtensionsJSON, expected, nil)
}

func TestParseExtensionsJSON_Malformed(t *testing.T) {
	// fixture mixes a valid entry with several malformed records
	// (missing dot, leading/trailing dot, no version). Only the valid one
	// should be emitted; malformed entries are silently skipped.
	fixture := "testdata/malformed/.vscode/extensions/extensions.json"
	locations := file.NewLocationSet(file.NewLocation(fixture).WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	expected := []pkg.Package{
		{
			Name:      "valid.entry",
			Version:   "1.0.0",
			Type:      pkg.VscodeExtensionPkg,
			PURL:      "pkg:vscode-extension/valid/entry@1.0.0",
			Locations: locations,
			Metadata: pkg.VscodeExtensionEntry{
				Publisher:            "valid",
				PublisherDisplayName: "Valid",
				UUID:                 "11111111-1111-1111-1111-111111111111",
			},
		},
	}

	pkgtest.TestFileParser(t, fixture, parseExtensionsJSON, expected, nil)
}

func TestSplitExtensionID(t *testing.T) {
	tests := []struct {
		input     string
		publisher string
		name      string
		ok        bool
	}{
		{"github.copilot-chat", "github", "copilot-chat", true},
		{"ms-vscode.cpptools-extension-pack", "ms-vscode", "cpptools-extension-pack", true},
		{"a.b.c", "a", "b.c", true}, // first dot is canonical
		{"single-token", "", "", false},
		{".leading-dot", "", "", false},
		{"trailing-dot.", "", "", false},
		{"", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			pub, n, ok := splitExtensionID(tt.input)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.publisher, pub)
			assert.Equal(t, tt.name, n)
		})
	}
}
