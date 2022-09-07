package model

import (
	"encoding/json"
	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestUnmarshalPackageGolang(t *testing.T) {
	tests := []struct {
		name        string
		packageData []byte
		assert      func(*Package)
	}{
		{
			name: "unmarshal package metadata",
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
			assert: func(p *Package) {
				assert.NotNil(t, p.Metadata)
				golangMetadata := p.Metadata.(pkg.GolangBinMetadata)
				assert.NotEmpty(t, golangMetadata)
				assert.Equal(t, "go1.18", golangMetadata.GoCompiledVersion)
			},
		},
		{
			name: "can handle package without metadata",
			packageData: []byte(`{
				"id": "8b594519bc23da50",
				"name": "gopkg.in/square/go-jose.v2",
				"version": "v2.6.0",
				"type": "go-module",
				"foundBy": "go-mod-cataloger",
				"locations": [
				  {
				    "path": "/Users/hal/go/bin/syft"
				  }
				],
				"licenses": [],
				"language": "go",
				"cpes": [],
				"purl": "pkg:golang/gopkg.in/square/go-jose.v2@v2.6.0"
			}`),
			assert: func(p *Package) {
				assert.Empty(t, p.MetadataType)
				assert.Empty(t, p.Metadata)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := &Package{}
			err := p.UnmarshalJSON(test.packageData)
			require.NoError(t, err)
			test.assert(p)
		})
	}
}

func Test_unpackMetadata(t *testing.T) {
	tests := []struct {
		name         string
		packageData  []byte
		metadataType pkg.MetadataType
		wantErr      require.ErrorAssertionFunc
	}{
		{
			name:         "unmarshal package metadata",
			metadataType: pkg.GolangBinMetadataType,
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
		{
			name:         "can handle package without metadata",
			metadataType: "",
			packageData: []byte(`{
				"id": "8b594519bc23da50",
				"name": "gopkg.in/square/go-jose.v2",
				"version": "v2.6.0",
				"type": "go-module",
				"foundBy": "go-mod-cataloger",
				"locations": [
				  {
				    "path": "/Users/hal/go/bin/syft"
				  }
				],
				"licenses": [],
				"language": "go",
				"cpes": [],
				"purl": "pkg:golang/gopkg.in/square/go-jose.v2@v2.6.0"
			}`),
		},
		{
			name:         "can handle RpmdbMetadata",
			metadataType: pkg.RpmMetadataType,
			packageData: []byte(`{
				"id": "4ac699c3b8fe1835",
				"name": "acl",
				"version": "2.2.53-1.el8",
				"type": "rpm",
				"foundBy": "rpm-db-cataloger",
				"locations": [
					{
					 "path": "/var/lib/rpm/Packages",
					 "layerID": "sha256:74ddd0ec08fa43d09f32636ba91a0a3053b02cb4627c35051aff89f853606b59"
					}
				],
				"licenses": [
					"GPLv2+"
				],
				"language": "",
				"cpes": [
					"cpe:2.3:a:centos:acl:2.2.53-1.el8:*:*:*:*:*:*:*",
					"cpe:2.3:a:acl:acl:2.2.53-1.el8:*:*:*:*:*:*:*"
				],
				"purl": "pkg:rpm/centos/acl@2.2.53-1.el8?arch=x86_64&upstream=acl-2.2.53-1.el8.src.rpm&distro=centos-8",
				"metadataType": "RpmdbMetadata",
				"metadata": {
					"name": "acl",
					"version": "2.2.53",
					"epoch": null,
					"architecture": "x86_64",
					"release": "1.el8",
					"sourceRpm": "acl-2.2.53-1.el8.src.rpm",
					"size": 205740,
					"license": "GPLv2+",
					"vendor": "CentOS",
					"modularityLabel": ""
				}
			}`),
		},
		{
			name:         "bad metadata type is an error",
			metadataType: "BOGOSITY",
			wantErr:      require.Error,
			packageData: []byte(`{
				"id": "8b594519bc23da50",
				"name": "gopkg.in/square/go-jose.v2",
				"version": "v2.6.0",
				"type": "go-module",
				"foundBy": "go-mod-cataloger",
				"locations": [
				  {
				    "path": "/Users/hal/go/bin/syft"
				  }
				],
				"licenses": [],
				"language": "go",
				"cpes": [],
				"purl": "pkg:golang/gopkg.in/square/go-jose.v2@v2.6.0",
				"metadataType": "BOGOSITY"
			}`),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.wantErr == nil {
				test.wantErr = require.NoError
			}
			p := &Package{}

			var basic PackageBasicData
			require.NoError(t, json.Unmarshal(test.packageData, &basic))
			p.PackageBasicData = basic

			var unpacker packageMetadataUnpacker
			require.NoError(t, json.Unmarshal(test.packageData, &unpacker))

			err := unpackMetadata(p, unpacker)
			assert.Equal(t, test.metadataType, p.MetadataType)
			test.wantErr(t, err)
		})
	}
}
