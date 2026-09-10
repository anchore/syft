package dotnet

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

func Test_packagesFromLogicalDepsJSON_skipsReferenceAssemblies(t *testing.T) {
	mkPkg := func(name, version, libType, sha, path string) logicalDepsJSONPackage {
		nv := name + "/" + version
		return logicalDepsJSONPackage{
			NameVersion: nv,
			Library:     &depsLibrary{Type: libType, Sha512: sha, Path: path},
			Targets: []depsTarget{
				{Runtime: map[string]map[string]string{"lib/" + name + ".dll": {}}},
			},
			RuntimePathsByRelativeDLLPath:  map[string]string{name + ".dll": "lib/" + name + ".dll"},
			ResourcePathsByRelativeDLLPath: map[string]string{},
			CompilePathsByRelativeDLLPath:  map[string]string{},
			NativePaths:                    strset.New(),
		}
	}

	realPkg := mkPkg("Real", "1.0.0", "package", "abc", "real/1.0.0")
	phantom := mkPkg("Phantom", "2.0.0", "referenceassembly", "", "")
	keptRef := mkPkg("KeptRef", "3.0.0", "referenceassembly", "xyz", "p")

	doc := logicalDepsJSON{
		Location: file.NewLocation("/app/Test.deps.json"),
		PackagesByNameVersion: map[string]logicalDepsJSONPackage{
			realPkg.NameVersion: realPkg,
			phantom.NameVersion: phantom,
			keptRef.NameVersion: keptRef,
		},
		PackageNameVersions: strset.New(realPkg.NameVersion, phantom.NameVersion, keptRef.NameVersion),
	}

	cfg := DefaultCatalogerConfig().
		WithDepPackagesMustClaimDLL(false).
		WithDepPackagesMustHaveDLL(false)

	_, pkgs, _ := packagesFromLogicalDepsJSON(doc, cfg)

	names := make(map[string]string)
	for _, p := range pkgs {
		names[p.Name] = p.Version
	}

	assert.Equal(t, "1.0.0", names["Real"])
	assert.Equal(t, "3.0.0", names["KeptRef"], "ref-asm w/ sha kept")
	assert.NotContains(t, names, "Phantom", "ref-asm w/o evidence skipped")

	for _, p := range pkgs {
		assert.Equal(t, pkg.DotnetPkg, p.Type)
	}
}

func Test_packagesFromLogicalDepsJSON_fixture_referenceassembly(t *testing.T) {
	const fixturePath = "testdata/deps-with-referenceassembly/MyApp.deps.json"

	raw, err := os.ReadFile(fixturePath)
	require.NoError(t, err)

	var deps depsJSON
	require.NoError(t, json.Unmarshal(raw, &deps))
	deps.Location = file.NewLocation("/app/MyApp.deps.json")

	doc := getLogicalDepsJSON(deps, nil)
	doc.Location = deps.Location

	cfg := DefaultCatalogerConfig().
		WithDepPackagesMustClaimDLL(false).
		WithDepPackagesMustHaveDLL(false)

	_, pkgs, _ := packagesFromLogicalDepsJSON(doc, cfg)

	names := make(map[string]string)
	for _, p := range pkgs {
		names[p.Name] = p.Version
	}

	assert.Equal(t, "13.0.3", names["Newtonsoft.Json"])
	assert.NotContains(t, names, "Microsoft.AspNetCore.DataProtection")
	assert.NotContains(t, names, "Microsoft.AspNetCore.DataProtection.Abstractions")

	for _, p := range pkgs {
		assert.NotEqual(t, "10.0.0.0", p.Version, "no 10.0.0.0 phantom")
	}
}
