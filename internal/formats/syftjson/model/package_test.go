package model

import "testing"

func TestUnmarshalPackage(t *testing.T) {
	tests := []struct {
		name        string
		p           *Package
		packageData []byte
	}{
		{
			name:        "Package.UnmarshalJSON will unmarshal blank json",
			p:           &Package{},
			packageData: []byte(`{}`),
		},
		{
			name: "Package.UnmarshalJSON unmarshals PackageBasicData",
			p:    &Package{},
			packageData: []byte(`{
				"id": "8b594519bc23da50",
				"name": "gopkg.in/square/go-jose.v2",
				"version": "v2.6.0",
				"type": "go-module",
				"foundBy": "go-module-binary-cataloger",
				"locations": [
				  {
				    "path": "/Users/hal/go/bin/syft"
				  }
				],
				"licenses": [],
				"language": "go",
				"cpes": [],
				"purl": "pkg:golang/gopkg.in/square/go-jose.v2@v2.6.0",
				"metadataType": "GolangBinMetadata",
				"metadata": {
				  "goCompiledVersion": "go1.18",
				  "architecture": "amd64",
				  "h1Digest": "h1:NGk74WTnPKBNUhNzQX7PYcTLUjoq7mzKk2OKbvwk2iI="
				}
			}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.p.UnmarshalJSON(test.packageData)
			if err != nil {
				t.Fatalf("could not unmarshal packageData: %v", err)
			}
		})
	}
}
