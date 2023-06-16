package spdxtagvalue

import (
	"bytes"
	"flag"
	"regexp"
	"testing"

	"github.com/anchore/syft/syft/formats/internal/testutils"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

var updateSnapshot = flag.Bool("update-spdx-tv", false, "update the *.golden files for spdx-tv encoders")
var updateImage = flag.Bool("update-image", false, "update the golden image used for image encoder testing")

func TestSPDXTagValueDirectoryEncoder(t *testing.T) {
	dir := t.TempDir()
	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		testutils.EncoderSnapshotTestConfig{
			Subject:                     testutils.DirectoryInput(t, dir),
			Format:                      Format(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
			Redactors: []testutils.Redactor{
				redactor{dir: dir}.redact,
			},
		},
	)
}

func TestSPDXTagValueImageEncoder(t *testing.T) {
	testImage := "image-simple"
	testutils.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutils.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutils.EncoderSnapshotTestConfig{
			Subject:                     testutils.ImageInput(t, testImage, testutils.FromSnapshot()),
			Format:                      Format(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
			Redactors: []testutils.Redactor{
				redactor{}.redact,
			},
		},
	)
}

func TestSPDXJSONSPDXIDs(t *testing.T) {
	var pkgs []pkg.Package
	for _, name := range []string{"some/slashes", "@at-sign", "under_scores"} {
		p := pkg.Package{
			Name: name,
		}
		p.SetID()
		pkgs = append(pkgs, p)
	}

	s := sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: pkg.NewCollection(pkgs...),
		},
		Relationships: nil,
		Source: source.Description{
			Metadata: source.DirectorySourceMetadata{Path: "foobar/baz"}, // in this case, foobar is used as the spdx docment name
		},
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "v0.42.0-bogus",
			Configuration: map[string]string{
				"config-key": "config-value",
			},
		},
	}

	testutils.AssertEncoderAgainstGoldenSnapshot(t,
		testutils.EncoderSnapshotTestConfig{
			Subject:                     s,
			Format:                      Format(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
			Redactors: []testutils.Redactor{
				redactor{}.redact,
			},
		},
	)
}

func TestSPDXRelationshipOrder(t *testing.T) {
	testImage := "image-simple"
	s := testutils.ImageInput(t, testImage, testutils.FromSnapshot())
	testutils.AddSampleFileRelationships(&s)

	testutils.AssertEncoderAgainstGoldenImageSnapshot(t,
		testutils.ImageSnapshotTestConfig{
			Image:               testImage,
			UpdateImageSnapshot: *updateImage,
		},
		testutils.EncoderSnapshotTestConfig{
			Subject:                     s,
			Format:                      Format(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
			Redactors: []testutils.Redactor{
				redactor{}.redact,
			},
		},
	)
}

type redactor struct {
	dir string
}

type replacement struct {
	pattern *regexp.Regexp
	replace string
}

func (r replacement) redact(b []byte) []byte {
	return r.pattern.ReplaceAll(b, []byte(r.replace))
}

func (r redactor) redact(s []byte) []byte {
	replacements := []replacement{
		// each SBOM reports the time it was generated, which is not useful during snapshot testing
		{
			pattern: regexp.MustCompile(`Created: .*`),
			replace: "Created: redacted",
		},

		// each SBOM reports a unique documentNamespace when generated, this is not useful for snapshot testing
		{
			pattern: regexp.MustCompile(`DocumentNamespace: https://anchore.com/syft/.*`),
			replace: "DocumentNamespace: redacted",
		},

		// the license list will be updated periodically, the value here should not be directly tested in snapshot tests
		{
			pattern: regexp.MustCompile(`LicenseListVersion: .*`),
			replace: "LicenseListVersion: redacted",
		},
	}

	for _, r := range replacements {
		s = r.redact(s)
	}

	if r.dir != "" {
		s = bytes.ReplaceAll(s, []byte(r.dir), []byte("redacted"))
	}

	return s
}
