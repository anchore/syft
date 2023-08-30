package model

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
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
				"licenses": [
				  {
				   "value": "MIT",
				   "spdxExpression": "MIT",
				   "type": "declared",
				   "url": []
				  }
				],
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
				"licenses": [
				  {
				    "value": "MIT",
					"spdxExpression": "MIT",
					"type": "declared",
					"url": ["https://www.github.com"]
				  },
				  {
				    "value": "MIT",
					"spdxExpression": "MIT",
					"type": "declared",
					"locations": [{"path": "/Users/hal/go/bin/syft"}]
				  }
				],
				"language": "go",
				"cpes": [],
				"purl": "pkg:golang/gopkg.in/square/go-jose.v2@v2.6.0"
			}`),
			assert: func(p *Package) {
				assert.Empty(t, p.MetadataType)
				assert.Empty(t, p.Metadata)
			},
		},
		{
			name: "can handle package with []string licenses",
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
				"licenses": ["MIT", "Apache-2.0"],
				"language": "go",
				"cpes": [],
				"purl": "pkg:golang/gopkg.in/square/go-jose.v2@v2.6.0"
			}`),
			assert: func(p *Package) {
				assert.Equal(t, licenses{
					{
						Value:          "MIT",
						SPDXExpression: "MIT",
						Type:           license.Declared,
					},
					{
						Value:          "Apache-2.0",
						SPDXExpression: "Apache-2.0",
						Type:           license.Declared,
					},
				}, p.Licenses)
			},
		},
		{
			name: "can handle package with []pkg.License licenses",
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
				"licenses": [	
					{
						"value": "MIT",
						"spdxExpression": "MIT",
						"type": "declared"
					},
					{
						"value": "Apache-2.0",
						"spdxExpression": "Apache-2.0",
						"type": "declared"
					}
				],
				"language": "go",
				"cpes": [],
				"purl": "pkg:golang/gopkg.in/square/go-jose.v2@v2.6.0"
			}`),
			assert: func(p *Package) {
				assert.Equal(t, licenses{
					{
						Value:          "MIT",
						SPDXExpression: "MIT",
						Type:           license.Declared,
					},
					{
						Value:          "Apache-2.0",
						SPDXExpression: "Apache-2.0",
						Type:           license.Declared,
					},
				}, p.Licenses)
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
		wantMetadata interface{}
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
		{
			name: "unknown metadata type",
			packageData: []byte(`{
				"metadataType": "NewMetadataType",
				"metadata": {
					"thing": "thing-1"
				}
			}`),
			wantErr:      require.Error,
			metadataType: "NewMetadataType",
			wantMetadata: map[string]interface{}{
				"thing": "thing-1",
			},
		},
		{
			name: "can handle package with metadata type but missing metadata",
			packageData: []byte(`{
				"metadataType": "GolangBinMetadata"
			}`),
			metadataType: pkg.GolangBinMetadataType,
			wantMetadata: pkg.GolangBinMetadata{},
		},
		{
			name: "can handle package with golang bin metadata type",
			packageData: []byte(`{
				"metadataType": "GolangBinMetadata"
			}`),
			metadataType: pkg.GolangBinMetadataType,
			wantMetadata: pkg.GolangBinMetadata{},
		},
		{
			name: "can handle package with unknonwn metadata type and missing metadata",
			packageData: []byte(`{
				"metadataType": "BadMetadata"
			}`),
			wantErr:      require.Error,
			metadataType: "BadMetadata",
			wantMetadata: nil,
		},
		{
			name: "can handle package with unknonwn metadata type and metadata",
			packageData: []byte(`{
				"metadataType": "BadMetadata",
				"metadata": {
					"random": "thing"
				}
			}`),
			wantErr:      require.Error,
			metadataType: "BadMetadata",
			wantMetadata: map[string]interface{}{
				"random": "thing",
			},
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

			err := unpackPkgMetadata(p, unpacker)
			assert.Equal(t, test.metadataType, p.MetadataType)
			test.wantErr(t, err)

			if test.wantMetadata != nil {
				assert.True(t, reflect.DeepEqual(test.wantMetadata, p.Metadata))
			}
		})
	}
}
