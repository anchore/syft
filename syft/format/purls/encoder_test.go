package purls

import (
	"flag"
	"testing"

	"github.com/anchore/syft/syft/format/internal/testutil"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

var updateSnapshot = flag.Bool("update-purl-list", false, "update the *.golden files for purl-list format")

func Test_Encoder(t *testing.T) {
	pkgs := []pkg.Package{
		{
			Name:     "npmtest",
			Version:  "1.5.1",
			Type:     pkg.NpmPkg,
			Language: pkg.JavaScript,
			PURL:     "pkg:npm/npmtest@1.0.0",
		},
		{
			Name:     "npmtest",
			Version:  "1.5.1",
			Type:     pkg.NpmPkg,
			Language: pkg.JavaScript,
			PURL:     "pkg:npm/npmtest@1.0.0", // duplicate should not be included
		},
		{
			Name:     "javatest",
			Version:  "0.30.1",
			Type:     pkg.JavaPkg,
			Language: pkg.Java,
			PURL:     "pkg:maven/org.apache/javatest@0.30.1",
		},
		{
			Type: pkg.UnknownPkg,
			PURL: "pkg:generic/generic@1.0.0",
		},
	}
	testutil.AssertEncoderAgainstGoldenSnapshot(t,
		testutil.EncoderSnapshotTestConfig{
			Subject: sbom.SBOM{Artifacts: sbom.Artifacts{
				Packages: pkg.NewCollection(pkgs...),
			}},
			Format:                      NewFormatEncoder(),
			UpdateSnapshot:              *updateSnapshot,
			PersistRedactionsInSnapshot: true,
			IsJSON:                      false,
		},
	)
}
