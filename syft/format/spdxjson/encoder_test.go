package spdxjson

import (
	"bytes"
	"flag"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/format/internal/spdxutil"
	"github.com/anchore/syft/syft/format/internal/testutil"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

var updateSnapshot = flag.Bool("update-spdx-json", false, "update the *.golden files for spdx-json encoders")
var updateImage = flag.Bool("update-image", false, "update the golden image used for image encoder testing")

func getEncoder(t testing.TB) sbom.FormatEncoder {
	cfg := DefaultEncoderConfig()
	cfg.Pretty = true

	enc, err := NewFormatEncoderWithConfig(cfg)
	require.NoError(t, err)
	return enc
}

func TestPrettyOutput(t *testing.T) {
	run := func(opt bool) string {
		enc, err := NewFormatEncoderWithConfig(EncoderConfig{
			Version: spdxutil.DefaultVersion,
			Pretty:  opt,
		})
		require.NoError(t, err)

		dir := t.TempDir()
		s := testutil.DirectoryInput(t, dir)

		var buffer bytes.Buffer
		err = enc.Encode(&buffer, s)
		require.NoError(t, err)

		return strings.TrimSpace(buffer.String())
	}

	t.Run("pretty", func(t *testing.T) {
		actual := run(true)
		assert.Contains(t, actual, "\n")
	})

	t.Run("compact", func(t *testing.T) {
		actual := run(false)
		assert.NotContains(t, actual, "\n")
	})
}

func TestEscapeHTML(t *testing.T) {
	dir := t.TempDir()
	s := testutil.DirectoryInput(t, dir)
	s.Artifacts.Packages.Add(pkg.Package{
		Name: "<html-package>",
	})

	// by default we do not escape HTML
	t.Run("default", func(t *testing.T) {
		cfg := DefaultEncoderConfig()

		enc, err := NewFormatEncoderWithConfig(cfg)
		require.NoError(t, err)

		var buffer bytes.Buffer
		err = enc.Encode(&buffer, s)
		require.NoError(t, err)

		actual := buffer.String()
		assert.Contains(t, actual, "<html-package>")
		assert.NotContains(t, actual, "\\u003chtml-package\\u003e")
	})

}

func TestSPDXJSONDirectoryEncoder(t *testing.T) {
	dir := t.TempDir()
	testutil.AssertEncoderAgainstGoldenSnapshot(t,
		testutil.EncoderSnapshotTestConfig{
			Subject:                     testutil.DirectoryInput(t, dir),
			Format:                      getEncoder(t),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      true,
			Redactor:                    redactor(dir),
		},
	)
}

func TestSPDXJSONImageEncoder(t *testing.T) {
	testImage := "image-simple"
	testutil.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutil.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutil.EncoderSnapshotTestConfig{
			Subject:                     testutil.ImageInput(t, testImage, testutil.FromSnapshot()),
			Format:                      getEncoder(t),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      true,
			Redactor:                    redactor(),
		},
	)
}

func TestSPDX22JSONRequredProperties(t *testing.T) {
	cfg := DefaultEncoderConfig()
	cfg.Pretty = true
	cfg.Version = "2.2"

	enc, err := NewFormatEncoderWithConfig(cfg)
	require.NoError(t, err)

	coords := file.NewCoordinates("/some/file", "ac897d978b6c38749a1")

	p1 := pkg.Package{
		Name:      "files-analyzed-true",
		Version:   "v1",
		Locations: file.NewLocationSet(file.NewLocation(coords.RealPath)),
		Licenses:  pkg.LicenseSet{},
		Language:  pkg.Java,
		Metadata: pkg.JavaArchive{
			ArchiveDigests: []file.Digest{
				{
					Algorithm: "sha256",
					Value:     "a9b87321a9879c79d87987987a97c97b9789ce978dffea987",
				},
			},
			Parent: nil,
		},
	}
	p1.SetID()

	p2 := pkg.Package{
		Name:    "files-analyzed-false",
		Version: "v2",
	}
	p2.SetID()

	testutil.AssertEncoderAgainstGoldenSnapshot(t,
		testutil.EncoderSnapshotTestConfig{
			Subject: sbom.SBOM{
				Artifacts: sbom.Artifacts{
					Packages: pkg.NewCollection(p1, p2),
					FileDigests: map[file.Coordinates][]file.Digest{
						coords: {
							{
								Algorithm: "sha1",
								Value:     "3b4ab96c371d913e2a88c269844b6c5fb5cbe761",
							},
						},
					},
				},
				Relationships: []artifact.Relationship{
					{
						From: p1,
						To:   coords,
						Type: artifact.ContainsRelationship,
					},
				},
			},
			Format:                      enc,
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      true,
			Redactor:                    redactor(),
		},
	)
}

func TestSPDXRelationshipOrder(t *testing.T) {
	testImage := "image-simple"

	s := testutil.ImageInput(t, testImage, testutil.FromSnapshot())
	testutil.AddSampleFileRelationships(&s)

	testutil.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutil.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutil.EncoderSnapshotTestConfig{
			Subject:                     s,
			Format:                      getEncoder(t),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      true,
			Redactor:                    redactor(),
		},
	)
}

func redactor(values ...string) testutil.Redactor {
	return testutil.NewRedactions().
		WithValuesRedacted(values...).
		WithPatternRedactors(
			map[string]string{
				// each SBOM reports the time it was generated, which is not useful during snapshot testing
				`"created":\s+"[^"]*"`: `"created":"redacted"`,

				// each SBOM reports a unique documentNamespace when generated, this is not useful for snapshot testing
				`"documentNamespace":\s+"[^"]*"`: `"documentNamespace":"redacted"`,

				// spdx3 IDs are URI with the documentnamespace spdxId containing a UID; namespace is the equivalent documentNamespace with the same value
				`"spdxId":\s+"[^"]*"`:    `"spdxId":"https://redacted"`,
				`"namespace":\s+"[^"]*"`: `"namespace":"https://redacted/"`,

				// the license list will be updated periodically, the value here should not be directly tested in snapshot tests
				`"licenseListVersion":\s+"[^"]*"`: `"licenseListVersion":"redacted"`,
			},
		)
}

func TestSupportedVersions(t *testing.T) {
	encs := defaultFormatEncoders()
	require.NotEmpty(t, encs)

	versions := SupportedVersions()
	require.Equal(t, len(versions), len(encs))

	subject := testutil.DirectoryInput(t, t.TempDir())
	dec := NewFormatDecoder()

	for _, enc := range encs {
		t.Run(enc.Version(), func(t *testing.T) {
			require.Contains(t, versions, enc.Version())

			var buf bytes.Buffer
			require.NoError(t, enc.Encode(&buf, subject))

			id, version := dec.Identify(bytes.NewReader(buf.Bytes()))
			assert.Equal(t, enc.ID(), id)
			assert.Equal(t, enc.Version(), version)

			var s *sbom.SBOM
			var err error
			s, id, version, err = dec.Decode(bytes.NewReader(buf.Bytes()))
			require.NoError(t, err)

			assert.Equal(t, enc.ID(), id)
			assert.Equal(t, enc.Version(), version)

			require.NotEmpty(t, s.Artifacts.Packages.PackageCount())

			assert.Equal(t, len(subject.Relationships), len(s.Relationships), "mismatched relationship count")

			if !assert.Equal(t, subject.Artifacts.Packages.PackageCount(), s.Artifacts.Packages.PackageCount(), "mismatched package count") {
				t.Logf("expected: %d", subject.Artifacts.Packages.PackageCount())
				for _, p := range subject.Artifacts.Packages.Sorted() {
					t.Logf("  - %s", p.String())
				}
				t.Logf("actual: %d", s.Artifacts.Packages.PackageCount())
				for _, p := range s.Artifacts.Packages.Sorted() {
					t.Logf("  - %s", p.String())
				}
			}
		})
	}
}

func defaultFormatEncoders() []sbom.FormatEncoder {
	var encs []sbom.FormatEncoder
	for _, version := range SupportedVersions() {
		enc, err := NewFormatEncoderWithConfig(EncoderConfig{Version: version})
		if err != nil {
			panic(err)
		}
		encs = append(encs, enc)
	}
	return encs
}

func TestEncodeDecodeTopLevelFiles(t *testing.T) {
	// the root package contains the top-level files, or the scanned root does when it is described
	root := file.NewCoordinates("", "")
	etc := file.NewCoordinates("/etc/os-release", "")
	jar := file.Coordinates{RealPath: "/app.war", FullPath: "/app.war!/WEB-INF/lib/a.jar"}
	war := file.NewCoordinates("/app.war", "")
	tests := []struct {
		name      string
		src       source.Description
		files     []file.Coordinates
		wantPaths []string
		wantRels  []string
	}{
		{
			name:      "img",
			src:       source.Description{Name: "img", Metadata: source.ImageMetadata{UserInput: "img:latest", ManifestDigest: "sha256:abc"}},
			files:     []file.Coordinates{etc, jar},
			wantPaths: []string{"etc/os-release", "app.war", "app.war!/WEB-INF/lib/a.jar"},
			wantRels:  []string{"app.war contains app.war!/WEB-INF/lib/a.jar"},
		},
		{
			name:      "dir",
			src:       source.Description{Name: "dir", Metadata: source.DirectoryMetadata{Path: "dir"}},
			files:     []file.Coordinates{etc, jar},
			wantPaths: []string{"etc/os-release", "app.war", "app.war!/WEB-INF/lib/a.jar"},
			wantRels:  []string{"app.war contains app.war!/WEB-INF/lib/a.jar"},
		},
		{
			name:      "dir-root",
			src:       source.Description{Name: "dir", Metadata: source.DirectoryMetadata{Path: "dir"}},
			files:     []file.Coordinates{root, etc, jar},
			wantPaths: []string{"", "etc/os-release", "app.war", "app.war!/WEB-INF/lib/a.jar"},
			wantRels:  []string{"app.war contains app.war!/WEB-INF/lib/a.jar"},
		},
		{
			// a scanned archive is the scanned root, holding what is at the root
			name:      "file",
			src:       source.Description{Name: "app.war", Metadata: source.FileMetadata{Path: "dir/app.war"}},
			files:     []file.Coordinates{war, jar},
			wantPaths: []string{"", "WEB-INF/lib/a.jar"},
		},
	}
	for _, tt := range tests {
		src := tt.src
		for _, enc := range defaultFormatEncoders() {
			t.Run(tt.name+"_"+enc.Version(), func(t *testing.T) {
				metadata := map[file.Coordinates]file.Metadata{}
				for _, c := range tt.files {
					metadata[c] = file.Metadata{}
				}
				var buf bytes.Buffer
				require.NoError(t, enc.Encode(&buf, sbom.SBOM{
					Source:    src,
					Artifacts: sbom.Artifacts{FileMetadata: metadata},
				}))

				s, _, _, err := NewFormatDecoder().Decode(bytes.NewReader(buf.Bytes()))
				require.NoError(t, err, "encoded document:\n%s", buf.String())

				assert.Equal(t, src.Name, s.Source.Name)
				assert.IsType(t, src.Metadata, s.Source.Metadata)

				var paths []string
				for c := range s.Artifacts.FileMetadata {
					paths = append(paths, c.FullNestedPath())
				}
				assert.ElementsMatch(t, tt.wantPaths, paths)

				var rels []string
				for _, r := range s.Relationships {
					from, _ := r.From.(file.Coordinates)
					to, _ := r.To.(file.Coordinates)
					rels = append(rels, from.FullNestedPath()+" "+string(r.Type)+" "+to.FullNestedPath())
				}
				assert.ElementsMatch(t, tt.wantRels, rels)
			})
		}
	}
}
