package cpegenerate

import (
	"testing"

	"github.com/anchore/syft/syft/pkg"
)

func TestGhostscriptPEGeneratesArtifexCPE(t *testing.T) {
	// construct a BinaryPkg with PE metadata resembling Ghostscript
	p := pkg.Package{
		Name:    "GPL Ghostscript",
		Version: "9.54.0",
		Type:    pkg.BinaryPkg,
		Metadata: pkg.PEBinary{
			VersionResources: pkg.KeyValues{
				{Key: "CompanyName", Value: "Artifex Software, Inc."},
				{Key: "ProductName", Value: "GPL Ghostscript"},
				{Key: "FileDescription", Value: "Ghostscript Interpreter"},
			},
		},
	}

	cpes := FromPackageAttributes(p)
	if len(cpes) == 0 {
		t.Fatalf("expected at least one CPE, got none")
	}

	found := false
	for _, c := range cpes {
		if c.Attributes.Vendor == "artifex" && c.Attributes.Product == "ghostscript" && c.Attributes.Version == p.Version {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected to find CPE with vendor 'artifex' and product 'ghostscript' for Ghostscript PE binary; got: %+v", cpes)
	}
}

func TestMicrosoftEdgePEGeneratesCorrectCPE(t *testing.T) {
	// construct a BinaryPkg with PE metadata resembling Microsoft Edge (e.g. msedge.exe)
	p := pkg.Package{
		Name:    "Microsoft Edge",
		Version: "122.0.2365.106",
		Type:    pkg.BinaryPkg,
		Metadata: pkg.PEBinary{
			VersionResources: pkg.KeyValues{
				{Key: "CompanyName", Value: "Microsoft Corporation"},
				{Key: "ProductName", Value: "Microsoft Edge"},
				{Key: "FileDescription", Value: "Microsoft Edge"},
			},
		},
	}

	cpes := FromPackageAttributes(p)
	if len(cpes) == 0 {
		t.Fatalf("expected at least one CPE, got none")
	}

	// the first CPE is the one selected as the package's primary CPE in output formats (e.g. CycloneDX),
	// so it must be the correct vendor/product pairing and not the raw "Microsoft_Edge:Microsoft_Edge" guess.
	got := cpes[0].Attributes
	if got.Vendor != "microsoft" || got.Product != "edge_chromium" || got.Version != p.Version {
		t.Fatalf("expected primary CPE vendor 'microsoft' and product 'edge_chromium' for Microsoft Edge PE binary; got: %+v", cpes)
	}

	for _, c := range cpes {
		if c.Attributes.Vendor == "microsoft_edge" || c.Attributes.Product == "microsoft_edge" {
			t.Fatalf("did not expect a CPE derived verbatim from the raised package name; got: %+v", cpes)
		}
	}
}
