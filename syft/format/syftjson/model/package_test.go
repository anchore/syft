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

func Test_UnmarshalJSON(t *testing.T) {
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
				require.NotNil(t, p.Metadata)
				golangMetadata := p.Metadata.(pkg.GolangBinaryBuildinfoEntry)
				require.NotEmpty(t, golangMetadata)
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
		{
			name: "breaking v11-v12 schema change: rpm db vs archive (select db)",
			packageData: []byte(`{
  "id": "739158935bfffc4d",
  "name": "dbus",
  "version": "1:1.12.8-12.el8",
  "type": "rpm",
  "foundBy": "rpm-db-cataloger",
  "locations": [
    {
      "path": "/var/lib/rpm/Packages",
      "layerID": "sha256:d871dadfb37b53ef1ca45be04fc527562b91989991a8f545345ae3be0b93f92a",
      "annotations": {
        "evidence": "primary"
      }
    }
  ],
  "licenses": [],
  "language": "",
  "cpes": [],
  "purl": "pkg:rpm/centos/dbus@1.12.8-12.el8?arch=aarch64&epoch=1&upstream=dbus-1.12.8-12.el8.src.rpm&distro=centos-8",
  "metadataType": "RpmMetadata",
  "metadata": {
    "name": "dbus",
    "version": "1.12.8",
    "epoch": 1,
    "architecture": "aarch64",
    "release": "12.el8",
    "sourceRpm": "dbus-1.12.8-12.el8.src.rpm",
    "size": 0,
    "vendor": "CentOS",
    "modularityLabel": "",
    "files": []
  }
}
`),
			assert: func(p *Package) {
				assert.Equal(t, pkg.RpmPkg, p.Type)
				assert.Equal(t, reflect.TypeOf(pkg.RpmDBEntry{}).Name(), reflect.TypeOf(p.Metadata).Name())
			},
		},
		{
			name: "breaking v11-v12 schema change: rpm db vs archive (select archive)",
			packageData: []byte(`{
  "id": "739158935bfffc4d",
  "name": "dbus",
  "version": "1:1.12.8-12.el8",
  "type": "rpm",
  "foundBy": "rpm-db-cataloger",
  "locations": [
    {
      "path": "/var/cache/dbus-1.12.8-12.el8.rpm",
      "layerID": "sha256:d871dadfb37b53ef1ca45be04fc527562b91989991a8f545345ae3be0b93f92a",
      "annotations": {
        "evidence": "primary"
      }
    }
  ],
  "licenses": [],
  "language": "",
  "cpes": [],
  "purl": "pkg:rpm/centos/dbus@1.12.8-12.el8?arch=aarch64&epoch=1&upstream=dbus-1.12.8-12.el8.src.rpm&distro=centos-8",
  "metadataType": "RpmMetadata",
  "metadata": {
    "name": "dbus",
    "version": "1.12.8",
    "epoch": 1,
    "architecture": "aarch64",
    "release": "12.el8",
    "sourceRpm": "dbus-1.12.8-12.el8.src.rpm",
    "size": 0,
    "vendor": "CentOS",
    "modularityLabel": "",
    "files": []
  }
}
`),
			assert: func(p *Package) {
				assert.Equal(t, pkg.RpmPkg, p.Type)
				assert.Equal(t, reflect.TypeOf(pkg.RpmArchive{}).Name(), reflect.TypeOf(p.Metadata).Name())
			},
		},
		{
			name: "breaking v11-v12 schema change: stack.yaml vs stack.yaml.lock (select stack.yaml)",
			packageData: []byte(`{
  "id": "46ff1a71f7715f38",
  "name": "hspec-discover",
  "version": "2.9.4",
  "type": "hackage",
  "foundBy": "haskell-cataloger",
  "locations": [
    {
      "path": "/stack.yaml",
      "annotations": {
        "evidence": "primary"
      }
    }
  ],
  "licenses": [],
  "language": "haskell",
  "cpes": [
    "cpe:2.3:a:hspec-discover:hspec-discover:2.9.4:*:*:*:*:*:*:*",
    "cpe:2.3:a:hspec-discover:hspec_discover:2.9.4:*:*:*:*:*:*:*",
    "cpe:2.3:a:hspec_discover:hspec-discover:2.9.4:*:*:*:*:*:*:*",
    "cpe:2.3:a:hspec_discover:hspec_discover:2.9.4:*:*:*:*:*:*:*",
    "cpe:2.3:a:hspec:hspec-discover:2.9.4:*:*:*:*:*:*:*",
    "cpe:2.3:a:hspec:hspec_discover:2.9.4:*:*:*:*:*:*:*"
  ],
  "purl": "pkg:hackage/hspec-discover@2.9.4",
  "metadataType": "HackageMetadataType",
  "metadata": {
    "name": "",
    "version": "",
    "pkgHash": "fbcf49ecfc3d4da53e797fd0275264cba776ffa324ee223e2a3f4ec2d2c9c4a6"
  }
}`),
			assert: func(p *Package) {
				assert.Equal(t, pkg.HackagePkg, p.Type)
				assert.Equal(t, reflect.TypeOf(pkg.HackageStackYamlEntry{}).Name(), reflect.TypeOf(p.Metadata).Name())
			},
		},
		{
			name: "breaking v11-v12 schema change: stack.yaml vs stack.yaml.lock (select stack.yaml.lock)",
			packageData: []byte(`{
  "id": "87939e95124ceb92",
  "name": "optparse-applicative",
  "version": "0.16.1.0",
  "type": "hackage",
  "foundBy": "haskell-cataloger",
  "locations": [
    {
      "path": "/stack.yaml.lock",
      "annotations": {
        "evidence": "primary"
      }
    }
  ],
  "licenses": [],
  "language": "haskell",
  "cpes": [
    "cpe:2.3:a:optparse-applicative:optparse-applicative:0.16.1.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:optparse-applicative:optparse_applicative:0.16.1.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:optparse_applicative:optparse-applicative:0.16.1.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:optparse_applicative:optparse_applicative:0.16.1.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:optparse:optparse-applicative:0.16.1.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:optparse:optparse_applicative:0.16.1.0:*:*:*:*:*:*:*"
  ],
  "purl": "pkg:hackage/optparse-applicative@0.16.1.0",
  "metadataType": "HackageMetadataType",
  "metadata": {
    "name": "",
    "version": "",
    "pkgHash": "418c22ed6a19124d457d96bc66bd22c93ac22fad0c7100fe4972bbb4ac989731",
    "snapshotURL": "https://raw.githubusercontent.com/commercialhaskell/stackage-snapshots/master/lts/19/14.yaml"
  }
}`),
			assert: func(p *Package) {
				assert.Equal(t, pkg.HackagePkg, p.Type)
				assert.Equal(t, reflect.TypeOf(pkg.HackageStackYamlLockEntry{}).Name(), reflect.TypeOf(p.Metadata).Name())
			},
		},
		{
			name: "breaking v11-v12 schema change: rust cargo.lock vs audit (select cargo.lock)",
			packageData: []byte(`{
  "id": "95124ceb9287939e",
  "name": "optpkg",
  "version": "1.16.1",
  "type": "hackage",
  "foundBy": "rust-cataloger",
  "locations": [
    {
      "path": "/cargo.lock",
      "annotations": {
        "evidence": "primary"
      }
    }
  ],
  "licenses": [],
  "language": "rust",
  "cpes": [],
  "purl": "pkg:cargo/optpkg@1.16.1",
  "metadataType": "RustCargoPackageMetadata",
  "metadata": {}
}`),
			assert: func(p *Package) {
				assert.Equal(t, pkg.HackagePkg, p.Type)
				assert.Equal(t, reflect.TypeOf(pkg.RustCargoLockEntry{}).Name(), reflect.TypeOf(p.Metadata).Name())
			},
		},
		{
			name: "breaking v11-v12 schema change: rust cargo.lock vs audit (select audit binary)",
			packageData: []byte(`{
  "id": "95124ceb9287939e",
  "name": "optpkg",
  "version": "1.16.1",
  "type": "hackage",
  "foundBy": "rust-cataloger",
  "locations": [
    {
      "path": "/my-binary",
      "annotations": {
        "evidence": "primary"
      }
    }
  ],
  "licenses": [],
  "language": "rust",
  "cpes": [],
  "purl": "pkg:cargo/optpkg@1.16.1",
  "metadataType": "RustCargoPackageMetadata",
  "metadata": {}
}`),
			assert: func(p *Package) {
				assert.Equal(t, pkg.HackagePkg, p.Type)
				assert.Equal(t, reflect.TypeOf(pkg.RustBinaryAuditEntry{}).Name(), reflect.TypeOf(p.Metadata).Name())
			},
		},
		{
			name: "map-based java metadata",
			packageData: []byte(`{
  "id": "e6f845bdaa69ddb2",
  "name": "SparseBitSet",
  "version": "1.2",
  "type": "java-archive",
  "foundBy": "java-archive-cataloger",
  "locations": [],
  "licenses": [],
  "language": "java",
  "cpes": [],
  "purl": "pkg:maven/com.zaxxer/SparseBitSet@1.2",
  "metadataType": "java-archive",
  "metadata": {
    "virtualPath": "/opt/solr-9.4.1/modules/extraction/lib/SparseBitSet-1.2.jar",
    "manifest": {
      "main": {
        "Archiver-Version": "Plexus Archiver",
        "Build-Jdk": "1.8.0_73",
        "Built-By": "lbayer",
        "Created-By": "Apache Maven 3.5.0",
        "Manifest-Version": "1.0"
      },
      "namedSections": {
        "META-INF/mailcap": {
          "SHA-256-Digest": "kXN4VupOQOJhduMGwxumj4ijmD/YAlz97a9Mp7CVXtk="
        },
        "META-INF/versions/9/module-info.class": {
          "SHA-256-Digest": "cMeIRa5l8DWPgrVWavr/6TKVBUGixVKGcu6yOTZMlKk="
        }
      }
    }
  }
}`),
			assert: func(p *Package) {
				meta := p.Metadata.(pkg.JavaArchive)
				manifest := meta.Manifest
				assert.Equal(t, "1.8.0_73", manifest.Main.MustGet("Build-Jdk"))
				require.Equal(t, 2, len(manifest.Sections))
				assert.Equal(t, "META-INF/mailcap", manifest.Sections[0].MustGet("Name"))
				assert.Equal(t, "kXN4VupOQOJhduMGwxumj4ijmD/YAlz97a9Mp7CVXtk=", manifest.Sections[0].MustGet("SHA-256-Digest"))
				assert.Equal(t, "META-INF/versions/9/module-info.class", manifest.Sections[1].MustGet("Name"))
				assert.Equal(t, "cMeIRa5l8DWPgrVWavr/6TKVBUGixVKGcu6yOTZMlKk=", manifest.Sections[1].MustGet("SHA-256-Digest"))
			},
		},
		{
			name: "pre key-value golang metadata",
			packageData: []byte(`{
  "id": "e348ed25484a94c9",
  "name": "github.com/anchore/syft",
  "version": "v0.101.1-SNAPSHOT-4c777834",
  "type": "go-module",
  "foundBy": "go-module-binary-cataloger",
  "locations": [
    {
      "path": "/syft",
      "layerID": "sha256:2274947a5f3527e48d8725a96646aefdcce3d99340c1eefb1e7c894043863c92",
      "accessPath": "/syft",
      "annotations": {
        "evidence": "primary"
      }
    }
  ],
  "licenses": [],
  "language": "go",
  "cpes": [
    "cpe:2.3:a:anchore:syft:v0.101.1-SNAPSHOT-4c777834:*:*:*:*:*:*:*"
  ],
  "purl": "pkg:golang/github.com/anchore/syft@v0.101.1-SNAPSHOT-4c777834",
  "metadataType": "go-module-buildinfo-entry",
  "metadata": {
    "goBuildSettings": {
      "-buildmode": "exe",
      "-compiler": "gc",
      "-ldflags": "-w -s -extldflags '-static' -X main.version=0.101.1-SNAPSHOT-4c777834 -X main.gitCommit=4c777834618b2ad8ad94cd200a45d6670bc1c013 -X main.buildDate=2024-01-22T16:43:49Z -X main.gitDescription=v0.101.1-4-g4c777834 ",
      "CGO_ENABLED": "0",
      "GOAMD64": "v1",
      "GOARCH": "amd64",
      "GOOS": "linux",
      "vcs": "git",
      "vcs.modified": "false",
      "vcs.revision": "4c777834618b2ad8ad94cd200a45d6670bc1c013",
      "vcs.time": "2024-01-22T16:31:41Z"
    },
    "goCompiledVersion": "go1.21.2",
    "architecture": "amd64",
    "mainModule": "github.com/anchore/syft"
  }
}
`),
			assert: func(p *Package) {
				buildInfo := p.Metadata.(pkg.GolangBinaryBuildinfoEntry)
				assert.Equal(t, "exe", buildInfo.BuildSettings.MustGet("-buildmode"))
			},
		},
		{
			name: "conan lock with legacy options",
			packageData: []byte(`{
  "id": "75eb35307226c921",
  "name": "boost",
  "version": "1.75.0",
  "type": "conan",
  "foundBy": "conan-cataloger",
  "locations": [
    {
      "path": "/conan.lock",
      "accessPath": "/conan.lock",
      "annotations": {
        "evidence": "primary"
      }
    }
  ],
  "licenses": [],
  "language": "c++",
  "cpes": [
    "cpe:2.3:a:boost:boost:1.75.0:*:*:*:*:*:*:*"
  ],
  "purl": "pkg:conan/boost@1.75.0",
  "metadataType": "c-conan-lock-entry",
  "metadata": {
    "ref": "boost/1.75.0#a9c318f067216f900900e044e7af4ab1",
    "package_id": "dc8aedd23a0f0a773a5fcdcfe1ae3e89c4205978",
    "prev": "b9d7912e6131dfa453c725593b36c808",
    "options": {
      "addr2line_location": "/usr/bin/addr2line",
      "asio_no_deprecated": "False",
      "zstd": "False"
    },
    "context": "host"
  }
}`),
			assert: func(p *Package) {
				metadata := p.Metadata.(pkg.ConanV1LockEntry)
				assert.Equal(t, "False", metadata.Options.MustGet("asio_no_deprecated"))
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
		wantMetadata any
		wantErr      require.ErrorAssertionFunc
	}{
		{
			name:         "unmarshal package metadata",
			wantMetadata: pkg.GolangBinaryBuildinfoEntry{},
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
			wantMetadata: nil,
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
			wantMetadata: pkg.RpmDBEntry{},
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
			name:    "bad metadata type is an error",
			wantErr: require.Error,
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
			wantErr: require.Error,
			wantMetadata: map[string]interface{}{
				"thing": "thing-1",
			},
		},
		{
			name: "can handle package with metadata type but missing metadata",
			packageData: []byte(`{
				"metadataType": "GolangBinMetadata"
			}`),
			wantMetadata: pkg.GolangBinaryBuildinfoEntry{},
		},
		{
			name: "can handle package with golang bin metadata type",
			packageData: []byte(`{
				"metadataType": "GolangBinMetadata"
			}`),
			wantMetadata: pkg.GolangBinaryBuildinfoEntry{},
		},
		{
			name: "can handle package with unknown metadata type and missing metadata",
			packageData: []byte(`{
				"metadataType": "BadMetadata"
			}`),
			wantErr: require.Error,
		},
		{
			name: "can handle package with unknown metadata type and metadata",
			packageData: []byte(`{
				"metadataType": "BadMetadata",
				"metadata": {
					"random": "thing"
				}
			}`),
			wantErr: require.Error,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.wantErr == nil {
				test.wantErr = require.NoError
			}
			p := &Package{}

			var unpacker packageMetadataUnpacker
			require.NoError(t, json.Unmarshal(test.packageData, &unpacker))

			err := unpackPkgMetadata(p, unpacker)
			test.wantErr(t, err)

			if test.wantMetadata != nil {
				if p.Metadata == nil {
					t.Fatalf("expected metadata to be populated")
					return
				}
				assert.Equal(t, reflect.TypeOf(test.wantMetadata).Name(), reflect.TypeOf(p.Metadata).Name())
			}
		})
	}
}
