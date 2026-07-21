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
