package cyclonedxjson

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_decodeJSON(t *testing.T) {
	tests := []struct {
		file     string
		err      bool
		distro   string
		packages []string
	}{
		{
			file:     "snapshot/TestCycloneDxDirectoryEncoder.golden",
			distro:   "debian:1.2.3",
			packages: []string{"package-1:1.0.1", "package-2:2.0.1"},
		},
		{
			file:     "snapshot/TestCycloneDxImageEncoder.golden",
			distro:   "debian:1.2.3",
			packages: []string{"package-1:1.0.1", "package-2:2.0.1"},
		},
		{
			file: "image-simple/Dockerfile",
			err:  true,
		},
	}
	for _, test := range tests {
		t.Run(test.file, func(t *testing.T) {
			reader, err := os.Open("test-fixtures/" + test.file)
			assert.NoError(t, err)

			if test.err {
				err = Format().Validate(reader)
				assert.Error(t, err)
				return
			}

			bom, err := Format().Decode(reader)

			assert.NoError(t, err)

			split := strings.SplitN(test.distro, ":", 2)
			name := split[0]
			version := split[1]
			assert.Equal(t, bom.Artifacts.LinuxDistribution.ID, name)
			assert.Equal(t, bom.Artifacts.LinuxDistribution.Version, version)

		pkgs:
			for _, pkg := range test.packages {
				split = strings.SplitN(pkg, ":", 2)
				name = split[0]
				version = split[1]
				for p := range bom.Artifacts.Packages.Enumerate() {
					if p.Name == name {
						assert.Equal(t, version, p.Version)
						continue pkgs
					}
				}
				assert.Fail(t, fmt.Sprintf("package should be present: %s", pkg))
			}
		})
	}
}
