package cyclonedxutil

import (
	"go/constant"
	"go/types"
	"regexp"
	"slices"
	"testing"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/tools/go/packages"
)

// Test_allSpecVersionsMapped loads the cyclonedx-go package's type information and enumerates every
// SpecVersion* constant it declares, asserting each one is present in our version maps. Upgrading
// cyclonedx-go to a release that adds a new spec version will fail this test until versions.go is updated.
func Test_allSpecVersionsMapped(t *testing.T) {
	const pkgPath = "github.com/CycloneDX/cyclonedx-go"

	pkgs, err := packages.Load(&packages.Config{Mode: packages.NeedName | packages.NeedTypes}, pkgPath)
	require.NoError(t, err)
	require.Len(t, pkgs, 1)

	pkg := pkgs[0]
	require.Empty(t, pkg.Errors, "errors loading %s", pkgPath)
	require.NotNil(t, pkg.Types, "no type info loaded for %s", pkgPath)

	// allVersions is the superset (json/common versions merged in), so it covers every spec version we map.
	mapped := make(map[cyclonedx.SpecVersion]struct{})
	for syftVersion, sv := range allVersions {
		// make sure the key matches the version it's mapped to
		require.Contains(t, sv.String(), syftVersion, "version %q is not correctly mapped to cyclonedx SpecVersion %q", syftVersion, sv.String())
		mapped[sv] = struct{}{}
	}

	specVersionConst := regexp.MustCompile(`^SpecVersion\d`)
	scope := pkg.Types.Scope()
	found := 0
	for _, name := range scope.Names() {
		if !specVersionConst.MatchString(name) {
			continue
		}
		c, ok := scope.Lookup(name).(*types.Const)
		if !ok {
			continue
		}
		found++
		val, ok := constant.Int64Val(c.Val())
		require.Truef(t, ok, "could not read int value of cyclonedx.%s", name)
		_, ok = mapped[cyclonedx.SpecVersion(val)]

		assert.Truef(t, ok, "cyclonedx.%s is not mapped in versions.go; add it when upgrading cyclonedx-go", name)
	}
	require.NotZero(t, found, "no SpecVersion* constants found in %s", pkgPath)
}

func Test_versionSort(t *testing.T) {
	// versionSort returns <0 when a<b, 0 when a==b, >0 when a>b; assert on sign rather than exact value.
	sign := func(n int) int {
		switch {
		case n < 0:
			return -1
		case n > 0:
			return 1
		default:
			return 0
		}
	}

	tests := []struct {
		name string
		a    string
		b    string
		want int
	}{
		{name: "equal single part", a: "1", b: "1", want: 0},
		{name: "equal two parts", a: "1.4", b: "1.4", want: 0},
		{name: "minor less than", a: "1.3", b: "1.4", want: -1},
		{name: "minor greater than", a: "1.6", b: "1.5", want: 1},
		{name: "major less than", a: "1.7", b: "2.0", want: -1},
		{name: "major greater than", a: "2.0", b: "1.7", want: 1},
		{name: "fewer parts sorts first", a: "1", b: "1.0", want: -1},
		{name: "more parts sorts last", a: "1.0", b: "1", want: 1},
		{name: "numeric not lexical (10 > 9)", a: "1.10", b: "1.9", want: 1},
		{name: "multi-digit major", a: "10.0", b: "9.0", want: 1},
		{name: "three parts equal", a: "1.4.0", b: "1.4.0", want: 0},
		{name: "three parts patch differs", a: "1.4.1", b: "1.4.0", want: 1},
		{name: "non-numeric equal falls through", a: "1.x", b: "1.x", want: 0},
		{name: "non-numeric string compare", a: "1.a", b: "1.b", want: -1},
		{name: "non-numeric side string compare", a: "1.2", b: "1.x", want: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sign(versionSort(tt.a, tt.b)))
			// comparator must be antisymmetric: swapping operands negates the sign.
			assert.Equal(t, -tt.want, sign(versionSort(tt.b, tt.a)))
		})
	}
}

func Test_versionSort_sortsSlice(t *testing.T) {
	versions := []string{"1.10", "1.2", "1", "2.0", "1.9", "1.0"}
	slices.SortFunc(versions, versionSort)
	assert.Equal(t, []string{"1", "1.0", "1.2", "1.9", "1.10", "2.0"}, versions)
}
