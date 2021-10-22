package spdx22json

import (
	"os"
	"testing"

	"github.com/anchore/syft/syft/pkg"
	"github.com/stretchr/testify/assert"
)

type decodePkgFields struct {
	version  string
	licenses []string
}

func TestDecoder(t *testing.T) {
	f, err := os.Open("test-fixtures/sboms/alpine-spdx.json")
	assert.NoError(t, err)
	c, _, _, _, err := decoder(f)
	assert.NoError(t, err)
	packages := c.Sorted()
	assert.Len(t, packages, 14)

	// we're only asserting certain fields since the current decoding process is lossy
	// note: decoding anything under pkg.Metadata is NOT supported at this time
	for _, p := range packages {
		switch p.Name {
		case "alpine-baselayout":
			assertPkg(t, p, decodePkgFields{
				version:  "3.2.0-r16",
				licenses: []string{"GPL-2.0-only"},
			})
		case "alpine-keys":
			assertPkg(t, p, decodePkgFields{
				version:  "2.3-r1",
				licenses: []string{"MIT"},
			})
		case "apk-tools":
			assertPkg(t, p, decodePkgFields{
				version:  "2.12.7-r0",
				licenses: []string{"GPL-2.0-only"},
			})
		case "busybox":
			assertPkg(t, p, decodePkgFields{
				version:  "1.33.1-r3",
				licenses: []string{"GPL-2.0-only"},
			})
		case "ca-certificates-bundle":
			assertPkg(t, p, decodePkgFields{
				version:  "20191127-r5",
				licenses: []string{"MPL-2.0", "MIT"},
			})
		case "libc-utils":
			assertPkg(t, p, decodePkgFields{
				version:  "0.7.2-r3",
				licenses: []string{"BSD-2-Clause", "BSD-3-Clause"},
			})
		case "libcrypto1.1":
			assertPkg(t, p, decodePkgFields{
				version:  "1.1.1l-r0",
				licenses: []string{"OpenSSL"},
			})
		case "libretls":
			assertPkg(t, p, decodePkgFields{
				version:  "3.3.3p1-r2",
				licenses: []string{"ISC"},
			})
		case "libssl1.1":
			assertPkg(t, p, decodePkgFields{
				version:  "1.1.1l-r0",
				licenses: []string{"OpenSSL"},
			})
		case "musl":
			assertPkg(t, p, decodePkgFields{
				version:  "1.2.2-r3",
				licenses: []string{"MIT"},
			})
		case "musl-utils":
			assertPkg(t, p, decodePkgFields{
				version:  "1.2.2-r3",
				licenses: []string{"MIT"},
			})
		case "scanelf":
			assertPkg(t, p, decodePkgFields{
				version:  "1.3.2-r0",
				licenses: []string{"GPL-2.0-only"},
			})
		case "ssl_client":
			assertPkg(t, p, decodePkgFields{
				version:  "1.33.1-r3",
				licenses: []string{"GPL-2.0-only"},
			})
		case "zlib":
			assertPkg(t, p, decodePkgFields{
				version:  "1.2.11-r3",
				licenses: []string{"Zlib"},
			})
		default:
			t.Errorf("unknown package: %q %+v", p.Name, p)
		}
	}
}

func assertPkg(t *testing.T, p *pkg.Package, f decodePkgFields) {
	assert.Equal(t, f.version, p.Version, "%q unexpected version", p.Name)
	assert.ElementsMatch(t, f.licenses, p.Licenses, "%q unexpected license set", p.Name)
}
