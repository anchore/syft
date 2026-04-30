package julia

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func TestParseManifestHappyPath(t *testing.T) {
	fixture := "testdata/happy-path"
	cataloger := NewPackageCataloger(DefaultCatalogerConfig())

	pkgtest.NewCatalogTester().
		FromDirectory(t, fixture).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
			if len(pkgs) != 13 {
				t.Errorf("expected 13 packages (excluding extras), got %d", len(pkgs))
			}

			for _, p := range pkgs {
				if p.Name == "DevDep" || p.Name == "IndirectDevDep" || p.Name == "OptionalDep" {
					t.Errorf("extras package %s should not be included when IncludeExtras=false", p.Name)
				}

				meta, ok := p.Metadata.(pkg.JuliaManifestEntry)
				if !ok {
					t.Errorf("expected JuliaManifestEntry metadata for %s", p.Name)
					continue
				}
				if meta.DependencyKind != runtimeKind {
					t.Errorf("expected runtime dependency kind for %s, got %s", p.Name, meta.DependencyKind)
				}
			}
		}).
		TestCataloger(t, cataloger)
}

func TestParseManifestHappyPathWithExtras(t *testing.T) {
	fixture := "testdata/happy-path"
	cfg := DefaultCatalogerConfig().WithIncludeExtras(true)
	cataloger := NewPackageCataloger(cfg)

	pkgtest.NewCatalogTester().
		FromDirectory(t, fixture).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
			if len(pkgs) != 16 {
				t.Errorf("expected 16 packages (including extras), got %d", len(pkgs))
			}

			kindCounts := map[string]int{runtimeKind: 0, testKind: 0, optionalKind: 0}
			for _, p := range pkgs {
				meta, ok := p.Metadata.(pkg.JuliaManifestEntry)
				if !ok {
					t.Errorf("expected JuliaManifestEntry metadata for %s", p.Name)
					continue
				}

				kindCounts[meta.DependencyKind]++

				switch p.Name {
				case "DevDep", "IndirectDevDep":
					if meta.DependencyKind != testKind {
						t.Errorf("expected test dependency kind for %s, got %s", p.Name, meta.DependencyKind)
					}
				case "OptionalDep":
					if meta.DependencyKind != optionalKind {
						t.Errorf("expected optional dependency kind for %s, got %s", p.Name, meta.DependencyKind)
					}
				default:
					if meta.DependencyKind != runtimeKind {
						t.Errorf("expected runtime dependency kind for %s, got %s", p.Name, meta.DependencyKind)
					}
				}
			}

			if kindCounts[testKind] != 2 {
				t.Errorf("expected 2 test dependencies (DevDep, IndirectDevDep), got %d", kindCounts[testKind])
			}
			if kindCounts[optionalKind] != 1 {
				t.Errorf("expected 1 optional dependency (OptionalDep), got %d", kindCounts[optionalKind])
			}
		}).
		TestCataloger(t, cataloger)
}

func TestParseManifestIncludesProjectExtraMissingFromManifest(t *testing.T) {
	fixture := "testdata/missing-extra"
	cfg := DefaultCatalogerConfig().WithIncludeExtras(true)
	cataloger := NewPackageCataloger(cfg)

	pkgtest.NewCatalogTester().
		FromDirectory(t, fixture).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
			if len(pkgs) != 2 {
				t.Fatalf("expected 2 packages, got %d", len(pkgs))
			}

			var foundCSV bool
			for _, p := range pkgs {
				if p.Name != "CSV" {
					continue
				}

				foundCSV = true
				if p.Version != "" {
					t.Errorf("expected missing extra to have unknown version, got %q", p.Version)
				}
				if p.PURL != "pkg:julia/CSV?uuid=336ed68f-0bac-5ca0-87d4-7b16caf5d00b" {
					t.Errorf("unexpected purl for missing extra: %s", p.PURL)
				}
				if p.Locations.ToSlice()[0].RealPath != "Project.toml" {
					t.Errorf("expected missing extra to use Project.toml as evidence, got %v", p.Locations.ToSlice())
				}
				meta, ok := p.Metadata.(pkg.JuliaManifestEntry)
				if !ok {
					t.Fatalf("expected JuliaManifestEntry metadata for missing extra")
				}
				if meta.UUID != "336ed68f-0bac-5ca0-87d4-7b16caf5d00b" {
					t.Errorf("unexpected UUID for missing extra: %s", meta.UUID)
				}
				if meta.DependencyKind != testKind {
					t.Errorf("expected missing extra to be a test dependency, got %s", meta.DependencyKind)
				}
				if len(meta.Deps) != 0 {
					t.Errorf("expected missing extra to have no dependencies, got %v", meta.Deps)
				}
			}

			if !foundCSV {
				t.Errorf("expected CSV extra package")
			}
			if len(relationships) != 0 {
				t.Errorf("expected no relationships for missing extra, got %d", len(relationships))
			}
		}).
		TestCataloger(t, cataloger)
}

func TestParseManifestNoDeps(t *testing.T) {
	fixture := "testdata/no-deps-v1.6"
	cataloger := NewPackageCataloger(DefaultCatalogerConfig())

	pkgtest.NewCatalogTester().
		FromDirectory(t, fixture).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
			if len(pkgs) != 0 {
				t.Errorf("expected 0 packages for empty manifest, got %d", len(pkgs))
			}
			if len(relationships) != 0 {
				t.Errorf("expected 0 relationships for empty manifest, got %d", len(relationships))
			}
		}).
		TestCataloger(t, cataloger)
}

func TestParseManifestNoManifestFile(t *testing.T) {
	fixture := "testdata/no-manifest"
	cataloger := NewPackageCataloger(DefaultCatalogerConfig())

	pkgtest.NewCatalogTester().
		FromDirectory(t, fixture).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
			if len(pkgs) != 0 {
				t.Errorf("expected 0 packages when Manifest.toml is missing, got %d", len(pkgs))
			}
		}).
		TestCataloger(t, cataloger)
}

func TestParseManifestShadowedDepv19(t *testing.T) {
	fixture := "testdata/shadowed-dep-v1.9"
	cataloger := NewPackageCataloger(DefaultCatalogerConfig())
	locationSet := file.NewLocationSet(file.NewLocation("Manifest.toml"))

	pkgA := pkg.Package{
		Name:      "A",
		Version:   "",
		PURL:      "pkg:julia/A?uuid=ead4f63c-334e-11e9-00e6-e7f0a5f21b60",
		Locations: locationSet,
		Language:  pkg.Julia,
		Type:      pkg.JuliaPkg,
		Metadata: pkg.JuliaManifestEntry{
			UUID:           "ead4f63c-334e-11e9-00e6-e7f0a5f21b60",
			Deps:           []string{"f41f7b98-334e-11e9-1257-49272045fb24"},
			DependencyKind: runtimeKind,
		},
	}

	pkgB1 := pkg.Package{
		Name:      "B",
		Version:   "",
		PURL:      "pkg:julia/B?uuid=f41f7b98-334e-11e9-1257-49272045fb24",
		Locations: locationSet,
		Language:  pkg.Julia,
		Type:      pkg.JuliaPkg,
		Metadata: pkg.JuliaManifestEntry{
			UUID:           "f41f7b98-334e-11e9-1257-49272045fb24",
			DependencyKind: runtimeKind,
		},
	}

	pkgB2 := pkg.Package{
		Name:      "B",
		Version:   "",
		PURL:      "pkg:julia/B?uuid=edca9bc6-334e-11e9-3554-9595dbb4349c",
		Locations: locationSet,
		Language:  pkg.Julia,
		Type:      pkg.JuliaPkg,
		Metadata: pkg.JuliaManifestEntry{
			UUID:           "edca9bc6-334e-11e9-3554-9595dbb4349c",
			DependencyKind: runtimeKind,
		},
	}

	expectedPkgs := []pkg.Package{
		pkgA,
		pkgB1,
		pkgB2,
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: pkgB1,
			To:   pkgA,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.TestCataloger(t, fixture, cataloger, expectedPkgs, expectedRelationships)
}

func TestParseManifestTwoPkgsSameName(t *testing.T) {
	fixture := "testdata/Manifest-two-pkgs-same-name.toml"
	location := file.NewLocation(fixture)
	parser := newManifestParser(DefaultCatalogerConfig())

	pkgA := pkg.Package{
		Name:      "A",
		Version:   "",
		PURL:      "pkg:julia/A?uuid=ead4f63c-334e-11e9-00e6-e7f0a5f21b60",
		Locations: file.NewLocationSet(location),
		Language:  pkg.Julia,
		Type:      pkg.JuliaPkg,
		Metadata: pkg.JuliaManifestEntry{
			UUID:           "ead4f63c-334e-11e9-00e6-e7f0a5f21b60",
			Deps:           []string{"f41f7b98-334e-11e9-1257-49272045fb24"},
			DependencyKind: runtimeKind,
		},
	}

	pkgB1 := pkg.Package{
		Name:      "B",
		Version:   "",
		PURL:      "pkg:julia/B?uuid=f41f7b98-334e-11e9-1257-49272045fb24",
		Locations: file.NewLocationSet(location),
		Language:  pkg.Julia,
		Type:      pkg.JuliaPkg,
		Metadata: pkg.JuliaManifestEntry{
			UUID:           "f41f7b98-334e-11e9-1257-49272045fb24",
			DependencyKind: runtimeKind,
		},
	}

	pkgB2 := pkg.Package{
		Name:      "B",
		Version:   "",
		PURL:      "pkg:julia/B?uuid=edca9bc6-334e-11e9-3554-9595dbb4349c",
		Locations: file.NewLocationSet(location),
		Language:  pkg.Julia,
		Type:      pkg.JuliaPkg,
		Metadata: pkg.JuliaManifestEntry{
			UUID:           "edca9bc6-334e-11e9-3554-9595dbb4349c",
			DependencyKind: runtimeKind,
		},
	}

	expectedPkgs := []pkg.Package{
		pkgA,
		pkgB1,
		pkgB2,
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: pkgB1,
			To:   pkgA,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.TestFileParser(t, fixture, parser.parseManifest, expectedPkgs, expectedRelationships)
}

func TestParseManifestWeakDeps(t *testing.T) {
	fixture := "testdata/weakdeps"
	cfg := DefaultCatalogerConfig().WithIncludeWeakDeps(true)
	cataloger := NewPackageCataloger(cfg)

	pkgtest.NewCatalogTester().
		FromDirectory(t, fixture).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
			if len(pkgs) != 2 {
				t.Errorf("expected 2 packages, got %d", len(pkgs))
			}

			for _, p := range pkgs {
				meta, ok := p.Metadata.(pkg.JuliaManifestEntry)
				if !ok {
					t.Errorf("expected JuliaManifestEntry metadata for %s", p.Name)
					continue
				}

				switch p.Name {
				case "A":
					if meta.DependencyKind != runtimeKind {
						t.Errorf("expected runtime dependency kind for A, got %s", meta.DependencyKind)
					}
				case "WeakDep":
					if meta.DependencyKind != optionalKind {
						t.Errorf("expected optional dependency kind for WeakDep, got %s", meta.DependencyKind)
					}
				default:
					t.Errorf("unexpected package: %s", p.Name)
				}
			}
		}).
		TestCataloger(t, cataloger)
}

func TestParseManifestWeakDepsArray(t *testing.T) {
	fixture := "testdata/weakdeps-array"
	cfg := DefaultCatalogerConfig().WithIncludeWeakDeps(true)
	cataloger := NewPackageCataloger(cfg)
	locationSet := file.NewLocationSet(file.NewLocation("Manifest.toml"))

	pkgA := pkg.Package{
		Name:      "A",
		Version:   "0.1.0",
		PURL:      "pkg:julia/A@0.1.0?uuid=11111111-1111-1111-1111-111111111111",
		Locations: locationSet,
		Language:  pkg.Julia,
		Type:      pkg.JuliaPkg,
		Metadata: pkg.JuliaManifestEntry{
			UUID:           "11111111-1111-1111-1111-111111111111",
			Deps:           []string{"00000000-0000-0000-0000-000000000000"},
			DependencyKind: runtimeKind,
		},
	}

	weakDep := pkg.Package{
		Name:      "WeakDep",
		Version:   "1.0.0",
		PURL:      "pkg:julia/WeakDep@1.0.0?uuid=00000000-0000-0000-0000-000000000000",
		Locations: locationSet,
		Language:  pkg.Julia,
		Type:      pkg.JuliaPkg,
		Metadata: pkg.JuliaManifestEntry{
			UUID:           "00000000-0000-0000-0000-000000000000",
			DependencyKind: optionalKind,
		},
	}

	expectedPkgs := []pkg.Package{
		pkgA,
		weakDep,
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: weakDep,
			To:   pkgA,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.TestCataloger(t, fixture, cataloger, expectedPkgs, expectedRelationships)
}

func TestParseManifestWeakDepsExcluded(t *testing.T) {
	fixture := "testdata/weakdeps"
	cataloger := NewPackageCataloger(DefaultCatalogerConfig())

	pkgtest.NewCatalogTester().
		FromDirectory(t, fixture).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
			if len(pkgs) != 1 {
				t.Errorf("expected 1 package, got %d", len(pkgs))
			}

			for _, p := range pkgs {
				if p.Name == "WeakDep" {
					t.Errorf("WeakDep should not be included when IncludeWeakDeps=false")
				}
			}
		}).
		TestCataloger(t, cataloger)
}

func TestParseManifestLegacyPkgdocsFormat(t *testing.T) {
	fixture := "testdata/Manifest-legacy-pkgdocs.toml"
	location := file.NewLocation(fixture)
	parser := newManifestParser(DefaultCatalogerConfig())

	pkgA := pkg.Package{
		Name:      "A",
		Version:   "",
		PURL:      "pkg:julia/A?uuid=ead4f63c-334e-11e9-00e6-e7f0a5f21b60",
		Locations: file.NewLocationSet(location),
		Language:  pkg.Julia,
		Type:      pkg.JuliaPkg,
		Metadata: pkg.JuliaManifestEntry{
			UUID:           "ead4f63c-334e-11e9-00e6-e7f0a5f21b60",
			Deps:           []string{"f41f7b98-334e-11e9-1257-49272045fb24"},
			DependencyKind: runtimeKind,
		},
	}

	pkgB1 := pkg.Package{
		Name:      "B",
		Version:   "",
		PURL:      "pkg:julia/B?uuid=f41f7b98-334e-11e9-1257-49272045fb24",
		Locations: file.NewLocationSet(location),
		Language:  pkg.Julia,
		Type:      pkg.JuliaPkg,
		Metadata: pkg.JuliaManifestEntry{
			UUID:           "f41f7b98-334e-11e9-1257-49272045fb24",
			DependencyKind: runtimeKind,
		},
	}

	pkgB2 := pkg.Package{
		Name:      "B",
		Version:   "",
		PURL:      "pkg:julia/B?uuid=edca9bc6-334e-11e9-3554-9595dbb4349c",
		Locations: file.NewLocationSet(location),
		Language:  pkg.Julia,
		Type:      pkg.JuliaPkg,
		Metadata: pkg.JuliaManifestEntry{
			UUID:           "edca9bc6-334e-11e9-3554-9595dbb4349c",
			DependencyKind: runtimeKind,
		},
	}

	expectedPkgs := []pkg.Package{
		pkgA,
		pkgB1,
		pkgB2,
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: pkgB1,
			To:   pkgA,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.TestFileParser(t, fixture, parser.parseManifest, expectedPkgs, expectedRelationships)
}

func TestParseManifestWeakDepsTransitive(t *testing.T) {
	fixture := "testdata/weakdeps-transitive"
	cfg := DefaultCatalogerConfig().WithIncludeWeakDeps(true)
	cataloger := NewPackageCataloger(cfg)
	locationSet := file.NewLocationSet(file.NewLocation("Manifest.toml"))

	pkgtest.NewCatalogTester().
		FromDirectory(t, fixture).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
			abstractFfts := pkg.Package{
				Name:      "AbstractFFTs",
				Version:   "1.3.1",
				Locations: locationSet,
				Language:  pkg.Julia,
				Type:      pkg.JuliaPkg,
				PURL:      "pkg:julia/AbstractFFTs@1.3.1?uuid=621f4979-c628-5d54-868e-fcf4e3e8185c",
				Metadata: pkg.JuliaManifestEntry{
					UUID:           "621f4979-c628-5d54-868e-fcf4e3e8185c",
					Deps:           []string{"d360d2e6-b24c-11e9-a2a3-2a2ae2dbcce4"},
					DependencyKind: runtimeKind,
				},
			}
			chainRulesCore := pkg.Package{
				Name:      "ChainRulesCore",
				Version:   "",
				Locations: locationSet,
				Language:  pkg.Julia,
				Type:      pkg.JuliaPkg,
				PURL:      "pkg:julia/ChainRulesCore?uuid=d360d2e6-b24c-11e9-a2a3-2a2ae2dbcce4",
				Metadata: pkg.JuliaManifestEntry{
					UUID:           "d360d2e6-b24c-11e9-a2a3-2a2ae2dbcce4",
					DependencyKind: optionalKind,
				},
			}

			expectedPkgs := []pkg.Package{
				abstractFfts,
				chainRulesCore,
			}

			expectedRelationships := []artifact.Relationship{
				{
					From: chainRulesCore,
					To:   abstractFfts,
					Type: artifact.DependencyOfRelationship,
				},
			}

			pkgtest.TestCataloger(t, fixture, cataloger, expectedPkgs, expectedRelationships)
		}).
		TestCataloger(t, cataloger)
}

// This is a grey area in Pkg.jl. For now we will assume the package is used at runtime.
func TestParseManifestSharedRuntimeWeakdep(t *testing.T) {
	fixture := "testdata/shared-runtime-weakdep"
	cfg := DefaultCatalogerConfig().WithIncludeWeakDeps(true)
	cataloger := NewPackageCataloger(cfg)
	locationSet := file.NewLocationSet(file.NewLocation("Manifest.toml"))

	pkgtest.NewCatalogTester().
		FromDirectory(t, fixture).
		ExpectsAssertion(func(t *testing.T, pkgs []pkg.Package, relationships []artifact.Relationship) {
			pkgA := pkg.Package{
				Name:      "A",
				Version:   "",
				Locations: locationSet,
				Language:  pkg.Julia,
				Type:      pkg.JuliaPkg,
				PURL:      "pkg:julia/A?uuid=11111111-1111-1111-1111-111111111111",
				Metadata: pkg.JuliaManifestEntry{
					UUID:           "11111111-1111-1111-1111-111111111111",
					DependencyKind: runtimeKind,
				},
			}

			expectedPkgs := []pkg.Package{
				pkgA,
			}

			pkgtest.TestCataloger(t, fixture, cataloger, expectedPkgs, nil)
		}).
		TestCataloger(t, cataloger)
}
