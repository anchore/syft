package spdxhelpers

import (
	"testing"

	spdx "github.com/spdx/tools-golang/spdx/v3/v3_0"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/license"
	"github.com/anchore/syft/syft/pkg"
)

func TestToSyftModelV3_documentConversion(t *testing.T) {
	// Build SPDX 3.0 elements
	pkg1 := &spdx.Package{
		ID:      "pkg-1-id",
		Name:    "pkg-1",
		Version: "1.0.0",
		ExternalIdentifiers: spdx.ExternalIdentifierList{
			&spdx.ExternalIdentifier{
				Type:               spdx.ExternalIdentifierType_PackageURL,
				Identifier:         "pkg:npm/pkg-1@1.0.0",
				IdentifierLocators: []spdx.URI{"pkg:npm/pkg-1@1.0.0"},
			},
		},
	}
	pkg2 := &spdx.Package{
		ID:      "pkg-2-id",
		Name:    "pkg-2",
		Version: "2.0.0",
		ExternalIdentifiers: spdx.ExternalIdentifierList{
			&spdx.ExternalIdentifier{
				Type:               spdx.ExternalIdentifierType_PackageURL,
				Identifier:         "pkg:npm/pkg-2@2.0.0",
				IdentifierLocators: []spdx.URI{"pkg:npm/pkg-2@2.0.0"},
			},
		},
	}

	file1 := &spdx.File{
		ID:   "file-1-id",
		Name: "/src/main.go",
		VerifiedUsing: spdx.IntegrityMethodList{
			&spdx.Hash{
				Algorithm: spdx.HashAlgorithm_Sha256,
				Value:     "abc123",
			},
		},
	}
	file2 := &spdx.File{
		ID:   "file-2-id",
		Name: "/src/util.go",
	}

	// licenses
	pkg1ConcludedLicense := &spdx.ListedLicense{Name: "MIT"}
	pkg1DeclaredLicense := &spdx.DisjunctiveLicenseSet{
		Members: spdx.LicenseInfoList{
			&spdx.ListedLicense{Name: "MIT"},
			&spdx.ListedLicense{Name: "Apache-2.0"},
		},
	}
	pkg2ConcludedLicense := &spdx.ConjunctiveLicenseSet{
		Members: spdx.LicenseInfoList{
			&spdx.ListedLicense{Name: "BSD-3-Clause"},
			&spdx.OrLaterOperator{
				SubjectLicense: &spdx.ListedLicense{Name: "GPL-2.0"},
			},
		},
	}

	// relationships
	pkg1DependsOnPkg2 := &spdx.Relationship{
		From: pkg1,
		To:   spdx.ElementList{pkg2},
		Type: spdx.RelationshipType_DependsOn,
	}
	pkg1ContainsFile1 := &spdx.Relationship{
		From: pkg1,
		To:   spdx.ElementList{file1},
		Type: spdx.RelationshipType_Contains,
	}
	pkg2ContainsFile2 := &spdx.Relationship{
		From: pkg2,
		To:   spdx.ElementList{file2},
		Type: spdx.RelationshipType_Contains,
	}
	pkg1HasConcludedLicense := &spdx.Relationship{
		From: pkg1,
		To:   spdx.ElementList{pkg1ConcludedLicense},
		Type: spdx.RelationshipType_HasConcludedLicense,
	}
	pkg1HasDeclaredLicense := &spdx.Relationship{
		From: pkg1,
		To:   spdx.ElementList{pkg1DeclaredLicense},
		Type: spdx.RelationshipType_HasDeclaredLicense,
	}
	pkg2HasConcludedLicense := &spdx.Relationship{
		From: pkg2,
		To:   spdx.ElementList{pkg2ConcludedLicense},
		Type: spdx.RelationshipType_HasConcludedLicense,
	}

	sbomElement := &spdx.SBOM{
		RootElements: spdx.ElementList{pkg1},
		Elements: spdx.ElementList{
			pkg1, pkg2,
			file1, file2,
			pkg1DependsOnPkg2,
			pkg1ContainsFile1,
			pkg2ContainsFile2,
			pkg1HasConcludedLicense,
			pkg1HasDeclaredLicense,
			pkg2HasConcludedLicense,
		},
	}

	doc := &spdx.Document{
		SpdxDocument: spdx.SpdxDocument{
			ID:           "https://example.org/test-doc",
			Name:         "test-document",
			RootElements: spdx.ElementList{sbomElement},
			Elements: spdx.ElementList{
				sbomElement,
				pkg1, pkg2,
				file1, file2,
				pkg1DependsOnPkg2,
				pkg1ContainsFile1,
				pkg2ContainsFile2,
				pkg1HasConcludedLicense,
				pkg1HasDeclaredLicense,
				pkg2HasConcludedLicense,
			},
		},
	}

	// Convert
	result, err := ToSyftModelV3(doc)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify packages
	allPkgs := result.Artifacts.Packages.Sorted()
	require.Len(t, allPkgs, 2, "expected 2 packages")

	pkgsByName := map[string]pkg.Package{}
	for _, p := range allPkgs {
		pkgsByName[p.Name] = p
	}

	syftPkg1, ok := pkgsByName["pkg-1"]
	require.True(t, ok, "pkg-1 not found")
	assert.Equal(t, "1.0.0", syftPkg1.Version)
	assert.Equal(t, "pkg:npm/pkg-1@1.0.0", syftPkg1.PURL)

	syftPkg2, ok := pkgsByName["pkg-2"]
	require.True(t, ok, "pkg-2 not found")
	assert.Equal(t, "2.0.0", syftPkg2.Version)
	assert.Equal(t, "pkg:npm/pkg-2@2.0.0", syftPkg2.PURL)

	// Verify pkg-1 licenses: concluded MIT + declared (MIT OR Apache-2.0)
	pkg1Licenses := syftPkg1.Licenses.ToSlice()
	require.NotEmpty(t, pkg1Licenses, "pkg-1 should have licenses")

	var pkg1Concluded, pkg1Declared []pkg.License
	for _, l := range pkg1Licenses {
		switch l.Type {
		case license.Concluded:
			pkg1Concluded = append(pkg1Concluded, l)
		case license.Declared:
			pkg1Declared = append(pkg1Declared, l)
		}
	}
	require.Len(t, pkg1Concluded, 1)
	assert.Equal(t, "MIT", pkg1Concluded[0].Value)
	require.Len(t, pkg1Declared, 1)
	assert.Equal(t, "(MIT OR Apache-2.0)", pkg1Declared[0].Value)

	// Verify pkg-2 licenses: concluded BSD-3-Clause AND GPL-2.0-only+
	pkg2Licenses := syftPkg2.Licenses.ToSlice()
	require.NotEmpty(t, pkg2Licenses, "pkg-2 should have licenses")

	var pkg2Concluded []pkg.License
	for _, l := range pkg2Licenses {
		if l.Type == license.Concluded {
			pkg2Concluded = append(pkg2Concluded, l)
		}
	}
	require.Len(t, pkg2Concluded, 1)
	assert.Equal(t, "BSD-3-Clause AND GPL-2.0+", pkg2Concluded[0].Value)

	// Verify files
	coords1 := file.Coordinates{RealPath: "/src/main.go"}
	digests, ok := result.Artifacts.FileDigests[coords1]
	require.True(t, ok, "file1 digests not found")
	require.Len(t, digests, 1)
	assert.Equal(t, "sha256", digests[0].Algorithm)
	assert.Equal(t, "abc123", digests[0].Value)

	coords2 := file.Coordinates{RealPath: "/src/util.go"}
	_, ok = result.Artifacts.FileMetadata[coords2]
	assert.True(t, ok, "file2 metadata not found")

	// Verify relationships
	require.NotEmpty(t, result.Relationships)

	foundDependsOn := false
	foundPkg1ContainsFile := false
	foundPkg2ContainsFile := false
	for _, rel := range result.Relationships {
		fromPkg, fromOk := rel.From.(pkg.Package)
		if !fromOk {
			continue
		}
		switch toPkg := rel.To.(type) {
		case pkg.Package:
			if fromPkg.Name == "pkg-2" && toPkg.Name == "pkg-1" && rel.Type == artifact.DependencyOfRelationship {
				foundDependsOn = true
			}
		case file.Location:
			if fromPkg.Name == "pkg-1" && toPkg.RealPath == "/src/main.go" && rel.Type == artifact.ContainsRelationship {
				foundPkg1ContainsFile = true
			}
			if fromPkg.Name == "pkg-2" && toPkg.RealPath == "/src/util.go" && rel.Type == artifact.ContainsRelationship {
				foundPkg2ContainsFile = true
			}
		}
	}
	assert.True(t, foundDependsOn, "expected pkg-2 DependencyOf pkg-1 relationship")
	assert.True(t, foundPkg1ContainsFile, "expected pkg-1 Contains /src/main.go relationship")
	assert.True(t, foundPkg2ContainsFile, "expected pkg-2 Contains /src/util.go relationship")
}

func Test_v3licenseInfoToExpression(t *testing.T) {
	tests := []struct {
		name     string
		info     spdx.AnyLicenseInfo
		expected string
	}{
		{
			name:     "listed license",
			info:     &spdx.ListedLicense{Name: "MIT"},
			expected: "MIT",
		},
		{
			name:     "custom license with ID",
			info:     &spdx.CustomLicense{ID: "LicenseRef-Custom-1", Name: "Custom License"},
			expected: "LicenseRef-Custom-1",
		},
		{
			name:     "custom license without ID falls back to name",
			info:     &spdx.CustomLicense{Name: "Custom License"},
			expected: "Custom License",
		},
		{
			name:     "license expression",
			info:     &spdx.LicenseExpression{LicenseExpression: "MIT AND Apache-2.0"},
			expected: "MIT AND Apache-2.0",
		},
		{
			name: "or-later operator",
			info: &spdx.OrLaterOperator{
				SubjectLicense: &spdx.ListedLicense{Name: "GPL-2.0"},
			},
			expected: "GPL-2.0+",
		},
		{
			name: "conjunctive license set (AND)",
			info: &spdx.ConjunctiveLicenseSet{
				Members: spdx.LicenseInfoList{
					&spdx.ListedLicense{Name: "MIT"},
					&spdx.ListedLicense{Name: "Apache-2.0"},
				},
			},
			expected: "MIT AND Apache-2.0",
		},
		{
			name: "disjunctive license set (OR)",
			info: &spdx.DisjunctiveLicenseSet{
				Members: spdx.LicenseInfoList{
					&spdx.ListedLicense{Name: "MIT"},
					&spdx.ListedLicense{Name: "Apache-2.0"},
				},
			},
			expected: "(MIT OR Apache-2.0)",
		},
		{
			name: "with-addition operator",
			info: &spdx.WithAdditionOperator{
				SubjectExtendableLicense: &spdx.ListedLicense{Name: "GPL-2.0-only"},
				SubjectAddition:          &spdx.ListedLicenseException{Name: "Classpath-exception-2.0"},
			},
			expected: "GPL-2.0-only WITH Classpath-exception-2.0",
		},
		{
			name: "nested: (MIT OR Apache-2.0) AND GPL-2.0",
			info: &spdx.ConjunctiveLicenseSet{
				Members: spdx.LicenseInfoList{
					&spdx.DisjunctiveLicenseSet{
						Members: spdx.LicenseInfoList{
							&spdx.ListedLicense{Name: "MIT"},
							&spdx.ListedLicense{Name: "Apache-2.0"},
						},
					},
					&spdx.ListedLicense{Name: "GPL-2.0-only"},
				},
			},
			expected: "(MIT OR Apache-2.0) AND GPL-2.0-only",
		},
		{
			name: "nested: GPL-2.0 WITH Classpath OR MIT",
			info: &spdx.DisjunctiveLicenseSet{
				Members: spdx.LicenseInfoList{
					&spdx.WithAdditionOperator{
						SubjectExtendableLicense: &spdx.ListedLicense{Name: "GPL-2.0-only"},
						SubjectAddition:          &spdx.ListedLicenseException{Name: "Classpath-exception-2.0"},
					},
					&spdx.ListedLicense{Name: "MIT"},
				},
			},
			expected: "(GPL-2.0-only WITH Classpath-exception-2.0 OR MIT)",
		},
		{
			name:     "nil returns empty",
			info:     nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v3licenseInfoToExpression(tt.info)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func Test_v3toSyftLicenses(t *testing.T) {
	tests := []struct {
		name        string
		licenseType license.Type
		licenses    []spdx.AnyLicenseInfo
		expected    []string
	}{
		{
			name:        "simple listed license",
			licenseType: license.Declared,
			licenses: []spdx.AnyLicenseInfo{
				&spdx.ListedLicense{Name: "MIT"},
			},
			expected: []string{"MIT"},
		},
		{
			name:        "conjunctive set produces single expression",
			licenseType: license.Concluded,
			licenses: []spdx.AnyLicenseInfo{
				&spdx.ConjunctiveLicenseSet{
					Members: spdx.LicenseInfoList{
						&spdx.ListedLicense{Name: "MIT"},
						&spdx.ListedLicense{Name: "Apache-2.0"},
					},
				},
			},
			expected: []string{"MIT AND Apache-2.0"},
		},
		{
			name:        "multiple license infos",
			licenseType: license.Declared,
			licenses: []spdx.AnyLicenseInfo{
				&spdx.ListedLicense{Name: "MIT"},
				&spdx.ListedLicense{Name: "GPL-2.0-only"},
			},
			expected: []string{"MIT", "GPL-2.0-only"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := v3toSyftLicenses(tt.licenseType, tt.licenses...)
			require.Len(t, got, len(tt.expected))
			for i, l := range got {
				assert.Equal(t, tt.licenseType, l.Type)
				assert.Equal(t, tt.expected[i], l.Value)
			}
		})
	}
}

func Test_v3parseSPDXLicenses(t *testing.T) {
	p := &spdx.Package{Name: "test-pkg"}

	concludedLicense := &spdx.ListedLicense{Name: "MIT"}
	declaredLicense := &spdx.ConjunctiveLicenseSet{
		Members: spdx.LicenseInfoList{
			&spdx.ListedLicense{Name: "Apache-2.0"},
			&spdx.ListedLicense{Name: "BSD-3-Clause"},
		},
	}

	relationships := ptrMap[[]spdx.AnyRelationship]{}
	relationships.Set(p, []spdx.AnyRelationship{
		&spdx.Relationship{
			Type: spdx.RelationshipType_HasConcludedLicense,
			From: p,
			To:   spdx.ElementList{concludedLicense},
		},
		&spdx.Relationship{
			Type: spdx.RelationshipType_HasDeclaredLicense,
			From: p,
			To:   spdx.ElementList{declaredLicense},
		},
	})

	licenses := v3parseSPDXLicenses(relationships, p)

	require.Len(t, licenses, 2)

	var concluded, declared []pkg.License
	for _, l := range licenses {
		switch l.Type {
		case license.Concluded:
			concluded = append(concluded, l)
		case license.Declared:
			declared = append(declared, l)
		}
	}

	require.Len(t, concluded, 1)
	assert.Equal(t, "MIT", concluded[0].Value)

	require.Len(t, declared, 1)
	assert.Equal(t, "Apache-2.0 AND BSD-3-Clause", declared[0].Value)
}
