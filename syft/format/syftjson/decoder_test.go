package syftjson

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/go-test/deep"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal/testutil"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func Test_EncodeDecodeCycle(t *testing.T) {

	table := []struct {
		name         string
		fixtureImage string
		cfg          EncoderConfig
	}{
		{
			name:         "go case",
			fixtureImage: "image-simple",
			cfg:          DefaultEncoderConfig(),
		},
		{
			name:         "default alpine",
			fixtureImage: "image-alpine",
			cfg:          DefaultEncoderConfig(),
		},
		{
			name:         "legacy alpine",
			fixtureImage: "image-alpine",
			cfg: EncoderConfig{
				Legacy: true,
			},
		},
	}

	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			originalSBOM := testutil.ImageInput(t, tt.fixtureImage)

			enc, err := NewFormatEncoderWithConfig(tt.cfg)
			require.NoError(t, err)
			dec := NewFormatDecoder()

			var buf bytes.Buffer
			assert.NoError(t, enc.Encode(&buf, originalSBOM))

			actualSBOM, decodedID, decodedVersion, err := dec.Decode(bytes.NewReader(buf.Bytes()))
			assert.NoError(t, err)
			assert.Equal(t, ID, decodedID)
			assert.Equal(t, internal.JSONSchemaVersion, decodedVersion)

			for _, d := range deep.Equal(originalSBOM.Source, actualSBOM.Source) {
				if strings.HasSuffix(d, "<nil slice> != []") {
					// semantically the same
					continue
				}
				t.Errorf("metadata difference: %+v", d)
			}

			actualPackages := actualSBOM.Artifacts.Packages.Sorted()
			for idx, p := range originalSBOM.Artifacts.Packages.Sorted() {
				if !assert.Equal(t, p.Name, actualPackages[idx].Name) {
					t.Errorf("different package at idx=%d: %s vs %s", idx, p.Name, actualPackages[idx].Name)
					continue
				}

				for _, d := range deep.Equal(p, actualPackages[idx]) {
					if strings.Contains(d, ".AccessPath: ") {
						// location.Virtual path is not exposed in the json output
						continue
					}
					if strings.HasSuffix(d, "<nil slice> != []") {
						// semantically the same
						continue
					}
					t.Errorf("%q package difference (%s): %+v", tt.fixtureImage, p.Name, d)
				}
			}
		})
	}
}

func TestOutOfDateParser(t *testing.T) {
	tests := []struct {
		name            string
		documentVersion string
		parserVersion   string
		want            error
	}{{
		name:            "no warning when doc version is older",
		documentVersion: "1.0.9",
		parserVersion:   "3.1.0",
	}, {
		name:            "warning when parser is older",
		documentVersion: "4.3.2",
		parserVersion:   "3.1.0",
		want:            fmt.Errorf("document has schema version %s, but parser has older schema version (%s)", "4.3.2", "3.1.0"),
	}, {
		name:            "warning when document version is unparseable",
		documentVersion: "some-nonsense",
		parserVersion:   "3.1.0",
		want:            fmt.Errorf("error comparing document schema version with parser schema version: %w", errors.New("Invalid Semantic Version")),
	}, {
		name:            "warning when parser version is unparseable",
		documentVersion: "7.1.0",
		parserVersion:   "some-nonsense",
		want:            fmt.Errorf("error comparing document schema version with parser schema version: %w", errors.New("Invalid Semantic Version")),
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkSupportedSchema(tt.documentVersion, tt.parserVersion)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_encodeDecodeFileMetadata(t *testing.T) {
	p := pkg.Package{
		Name:    "pkg",
		Version: "version",
		FoundBy: "something",
		Locations: file.NewLocationSet(file.Location{
			LocationData: file.LocationData{
				Coordinates: file.Coordinates{
					RealPath:     "/somewhere",
					FileSystemID: "id",
				},
			},
			LocationMetadata: file.LocationMetadata{
				Annotations: map[string]string{
					"key": "value",
				},
			},
		}),
		Licenses: pkg.NewLicenseSet(pkg.License{
			Value:          "MIT",
			SPDXExpression: "MIT",
			Type:           "MIT",
			URLs:           []string{"https://example.org/license"},
			Locations:      file.LocationSet{},
		}),
		Language: "language",
		Type:     "type",
		CPEs: []cpe.CPE{
			{
				Attributes: cpe.Attributes{
					Part:    "a",
					Vendor:  "vendor",
					Product: "product",
					Version: "version",
					Update:  "update",
				},
				Source: "test-source",
			},
		},
		PURL:     "pkg:generic/pkg@version",
		Metadata: nil,
	}
	p.SetID()

	c := file.Coordinates{
		RealPath:     "some-file",
		FileSystemID: "some-fs-id",
	}

	s := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(p),
			FileMetadata: map[file.Coordinates]file.Metadata{
				c: {
					FileInfo: stereoscopeFile.ManualInfo{
						NameValue: c.RealPath,
						ModeValue: 0644,
						SizeValue: 7,
					},
					Path:     c.RealPath,
					Type:     stereoscopeFile.TypeRegular,
					UserID:   1,
					GroupID:  2,
					MIMEType: "text/plain",
				},
			},
			FileDigests: map[file.Coordinates][]file.Digest{
				c: {
					{
						Algorithm: "sha1",
						Value:     "d34db33f",
					},
				},
			},
			FileContents: map[file.Coordinates]string{
				c: "some contents",
			},
			FileLicenses: map[file.Coordinates][]file.License{
				c: {
					{
						Value:          "MIT",
						SPDXExpression: "MIT",
						Type:           "MIT",
						LicenseEvidence: &file.LicenseEvidence{
							Confidence: 1,
							Offset:     2,
							Extent:     3,
						},
					},
				},
			},
			Unknowns: map[file.Coordinates][]string{},
			Executables: map[file.Coordinates]file.Executable{
				c: {
					Format: file.ELF,
					ELFSecurityFeatures: &file.ELFSecurityFeatures{
						SymbolTableStripped:           false,
						StackCanary:                   boolRef(true),
						NoExecutable:                  false,
						RelocationReadOnly:            "partial",
						PositionIndependentExecutable: false,
						DynamicSharedObject:           false,
						LlvmSafeStack:                 boolRef(false),
						LlvmControlFlowIntegrity:      boolRef(true),
						ClangFortifySource:            boolRef(true),
					},
				},
			},
			LinuxDistribution: &linux.Release{
				PrettyName:       "some os",
				Name:             "os",
				ID:               "os-id",
				IDLike:           []string{"os"},
				Version:          "version",
				VersionID:        "version",
				VersionCodename:  "codename",
				BuildID:          "build-id",
				ImageID:          "image-id",
				ImageVersion:     "image-version",
				Variant:          "variant",
				VariantID:        "variant-id",
				HomeURL:          "https://example.org/os",
				SupportURL:       "https://example.org/os/support",
				BugReportURL:     "https://example.org/os/bugs",
				PrivacyPolicyURL: "https://example.org/os/privacy",
				CPEName:          "os-cpe",
				SupportEnd:       "now",
			},
		},
		Relationships: nil,
		Source: source.Description{
			ID:      "some-id",
			Name:    "some-name",
			Version: "some-version",
			Metadata: source.FileMetadata{
				Path: "/some-file-source-path",
				Digests: []file.Digest{
					{
						Algorithm: "sha1",
						Value:     "d34db33f",
					},
				},
				MIMEType: "file/zip",
			},
		},
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "this-version",
		},
	}

	buf := &bytes.Buffer{}
	enc := NewFormatEncoder()
	err := enc.Encode(buf, s)
	require.NoError(t, err)

	dec := NewFormatDecoder()

	got, decodedID, decodedVersion, err := dec.Decode(bytes.NewReader(buf.Bytes()))
	require.NoError(t, err)
	assert.Equal(t, ID, decodedID)
	assert.Equal(t, internal.JSONSchemaVersion, decodedVersion)

	require.Equal(t, s, *got)
}
