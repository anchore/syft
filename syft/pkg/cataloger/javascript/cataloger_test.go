package javascript

import (
	"testing"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func expectedPackagesAndRelationshipsLockV1(locationSet file.LocationSet, metadata bool) ([]pkg.Package, []artifact.Relationship) {
	metadataMap := map[string]pkg.NpmPackageLockJSONMetadata{
		"rxjs": {
			Resolved:  "https://registry.npmjs.org/rxjs/-/rxjs-7.5.7.tgz",
			Integrity: "sha512-z9MzKh/UcOqB3i20H6rtrlaE/CgjLOvheWK/9ILrbhROGTweAi1BaFsTT9FbwZi5Trr1qNRs+MXkhmR06awzQA==",
		},
		"test-app": {
			Resolved:  "",
			Integrity: "",
		},
		"typescript": {
			Resolved:  "https://registry.npmjs.org/typescript/-/typescript-4.7.4.tgz",
			Integrity: "sha512-C0WQT0gezHuw6AdY1M2jxUO83Rjf0HP7Sk1DtXj6j1EwkQNZrHAg2XPWlq62oqEhYvONq5pkC2Y9oPljWToLmQ==",
		},
		"tslib": {
			Resolved:  "https://registry.npmjs.org/tslib/-/tslib-2.6.2.tgz",
			Integrity: "sha512-AEYxH93jGFPn/a2iVAwW87VuUIkR1FVUKB77NwMF7nBTDkDrrT/Hpt/IrCJ0QXhW27jTBDcf5ZY7w6RiqTMw2Q==",
		},
		"zone.js": {
			Resolved:  "https://registry.npmjs.org/zone.js/-/zone.js-0.11.8.tgz",
			Integrity: "sha512-82bctBg2hKcEJ21humWIkXRlLBBmrc3nN7DFh5LGGhcyycO2S7FN8NmdvlcKaGFDNVL4/9kFLmwmInTavdJERA==",
		},
	}
	rxjs := pkg.Package{
		Name:         "rxjs",
		Version:      "7.5.7",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/rxjs@7.5.7",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	testApp := pkg.Package{
		Name:         "test-app",
		Version:      "0.0.0",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/test-app@0.0.0",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	tslib := pkg.Package{
		Name:         "tslib",
		Version:      "2.6.2",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/tslib@2.6.2",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	typescript := pkg.Package{
		Name:         "typescript",
		Version:      "4.7.4",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/typescript@4.7.4",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	zonejs := pkg.Package{
		Name:         "zone.js",
		Version:      "0.11.8",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/zone.js@0.11.8",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}

	l := []*pkg.Package{
		&rxjs,
		&testApp,
		&tslib,
		&typescript,
		&zonejs,
	}

	var expectedPkgs []pkg.Package
	for i := range l {
		if metadata {
			l[i].Metadata = metadataMap[l[i].Name]
			expectedPkgs = append(expectedPkgs, *l[i])
		} else {
			expectedPkgs = append(expectedPkgs, *l[i])
		}
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: rxjs,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: tslib,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: typescript,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: zonejs,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
	}

	return expectedPkgs, expectedRelationships
}

func expectedPackagesAndRelationshipsLockV2(locationSet file.LocationSet, metadata bool) ([]pkg.Package, []artifact.Relationship) {
	metadataMap := map[string]pkg.NpmPackageLockJSONMetadata{
		"rxjs": {
			Resolved:  "https://registry.npmjs.org/rxjs/-/rxjs-7.5.7.tgz",
			Integrity: "sha512-z9MzKh/UcOqB3i20H6rtrlaE/CgjLOvheWK/9ILrbhROGTweAi1BaFsTT9FbwZi5Trr1qNRs+MXkhmR06awzQA==",
		},
		"test-app": {
			Resolved:  "",
			Integrity: "",
		},
		"tslib": {
			Resolved:  "https://registry.npmjs.org/tslib/-/tslib-2.4.1.tgz",
			Integrity: "sha512-tGyy4dAjRIEwI7BzsB0lynWgOpfqjUdq91XXAlIWD2OwKBH7oCl/GZG/HT4BOHrTlPMOASlMQ7veyTqpmRcrNA==",
		},
		"typescript": {
			Resolved:  "https://registry.npmjs.org/typescript/-/typescript-4.7.4.tgz",
			Integrity: "sha512-C0WQT0gezHuw6AdY1M2jxUO83Rjf0HP7Sk1DtXj6j1EwkQNZrHAg2XPWlq62oqEhYvONq5pkC2Y9oPljWToLmQ==",
		},
		"zone.js": {
			Resolved:  "https://registry.npmjs.org/zone.js/-/zone.js-0.11.8.tgz",
			Integrity: "sha512-82bctBg2hKcEJ21humWIkXRlLBBmrc3nN7DFh5LGGhcyycO2S7FN8NmdvlcKaGFDNVL4/9kFLmwmInTavdJERA==",
		},
	}
	rxjs := pkg.Package{
		Name:         "rxjs",
		Version:      "7.5.7",
		PURL:         "pkg:npm/rxjs@7.5.7",
		Locations:    locationSet,
		Licenses:     pkg.NewLicenseSet(),
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	testApp := pkg.Package{
		Name:         "test-app",
		Version:      "0.0.0",
		PURL:         "pkg:npm/test-app@0.0.0",
		Locations:    locationSet,
		Licenses:     pkg.NewLicenseSet(),
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	tslib := pkg.Package{
		Name:         "tslib",
		Version:      "2.4.1",
		PURL:         "pkg:npm/tslib@2.4.1",
		Locations:    locationSet,
		Licenses:     pkg.NewLicenseSet(),
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	typescript := pkg.Package{
		Name:         "typescript",
		Version:      "4.7.4",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/typescript@4.7.4",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	zonejs := pkg.Package{
		Name:         "zone.js",
		Version:      "0.11.8",
		PURL:         "pkg:npm/zone.js@0.11.8",
		Locations:    locationSet,
		Licenses:     pkg.NewLicenseSet(),
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}

	l := []*pkg.Package{
		&rxjs,
		&testApp,
		&tslib,
		&typescript,
		&zonejs,
	}

	var expectedPkgs []pkg.Package
	for i := range l {
		if metadata {
			l[i].Metadata = metadataMap[l[i].Name]
			expectedPkgs = append(expectedPkgs, *l[i])
		} else {
			expectedPkgs = append(expectedPkgs, *l[i])
		}
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: rxjs,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: tslib,
			To:   rxjs,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: tslib,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: tslib,
			To:   zonejs,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: typescript,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: zonejs,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
	}

	return expectedPkgs, expectedRelationships
}

func expectedPackagesAndRelationshipsYarnLock(locationSet file.LocationSet, metadata bool) ([]pkg.Package, []artifact.Relationship) {
	metadataMap := map[string]pkg.NpmPackageLockJSONMetadata{
		"rxjs": {
			Resolved:  "https://registry.npmjs.org/rxjs/-/rxjs-7.5.7.tgz",
			Integrity: "sha512-z9MzKh/UcOqB3i20H6rtrlaE/CgjLOvheWK/9ILrbhROGTweAi1BaFsTT9FbwZi5Trr1qNRs+MXkhmR06awzQA==",
		},
		"test-app": {
			Resolved:  "",
			Integrity: "",
		},
		"tslib": {
			Resolved:  "https://registry.npmjs.org/tslib/-/tslib-2.4.1.tgz",
			Integrity: "sha512-tGyy4dAjRIEwI7BzsB0lynWgOpfqjUdq91XXAlIWD2OwKBH7oCl/GZG/HT4BOHrTlPMOASlMQ7veyTqpmRcrNA==",
		},
		"typescript": {
			Resolved:  "https://registry.npmjs.org/typescript/-/typescript-4.7.4.tgz",
			Integrity: "sha512-C0WQT0gezHuw6AdY1M2jxUO83Rjf0HP7Sk1DtXj6j1EwkQNZrHAg2XPWlq62oqEhYvONq5pkC2Y9oPljWToLmQ==",
		},
		"zone.js": {
			Resolved:  "https://registry.npmjs.org/zone.js/-/zone.js-0.11.8.tgz",
			Integrity: "sha512-82bctBg2hKcEJ21humWIkXRlLBBmrc3nN7DFh5LGGhcyycO2S7FN8NmdvlcKaGFDNVL4/9kFLmwmInTavdJERA==",
		},
	}
	rxjs := pkg.Package{
		Name:         "rxjs",
		Version:      "7.5.7",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/rxjs@7.5.7",
		Locations:    locationSet,
		Licenses:     pkg.NewLicenseSet(),
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	testApp := pkg.Package{
		Name:         "test-app",
		Version:      "0.0.0",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/test-app@0.0.0",
		Locations:    locationSet,
		Licenses:     pkg.NewLicenseSet(),
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	tslib := pkg.Package{
		Name:         "tslib",
		Version:      "2.4.1",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/tslib@2.4.1",
		Locations:    locationSet,
		Licenses:     pkg.NewLicenseSet(),
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	typescript := pkg.Package{
		Name:         "typescript",
		Version:      "4.7.4",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/typescript@4.7.4",
		Locations:    locationSet,
		Licenses:     pkg.NewLicenseSet(),
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
	}
	zonejs := pkg.Package{
		Name:         "zone.js",
		Version:      "0.11.8",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/zone.js@0.11.8",
		Locations:    locationSet,
		Licenses:     pkg.NewLicenseSet(),
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}

	l := []*pkg.Package{
		&rxjs,
		&testApp,
		&tslib,
		&typescript,
		&zonejs,
	}

	var expectedPkgs []pkg.Package
	for i := range l {
		if metadata {
			l[i].Metadata = metadataMap[l[i].Name]
			expectedPkgs = append(expectedPkgs, *l[i])
		} else {
			expectedPkgs = append(expectedPkgs, *l[i])
		}
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: rxjs,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: tslib,
			To:   rxjs,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: tslib,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: tslib,
			To:   zonejs,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: typescript,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: zonejs,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
	}

	return expectedPkgs, expectedRelationships
}

func expectedPackagesAndRelationshipsLockV3(locationSet file.LocationSet, metadata bool) ([]pkg.Package, []artifact.Relationship) {
	metadataMap := map[string]pkg.NpmPackageLockJSONMetadata{
		"rxjs": {
			Resolved:  "https://registry.npmjs.org/rxjs/-/rxjs-7.5.0.tgz",
			Integrity: "sha512-fuCKAfFawVYX0pyFlETtYnXI+5iiY9Dftgk+VdgeOq+Qyi9ZDWckHZRDaXRt5WCNbbLkmAheoSGDiceyCIKNZA==",
		},
		"test-app": {
			Resolved:  "",
			Integrity: "",
		},
		"tslib": {
			Resolved:  "https://registry.npmjs.org/tslib/-/tslib-2.6.2.tgz",
			Integrity: "sha512-AEYxH93jGFPn/a2iVAwW87VuUIkR1FVUKB77NwMF7nBTDkDrrT/Hpt/IrCJ0QXhW27jTBDcf5ZY7w6RiqTMw2Q==",
		},
		"typescript": {
			Resolved:  "https://registry.npmjs.org/typescript/-/typescript-4.7.4.tgz",
			Integrity: "sha512-C0WQT0gezHuw6AdY1M2jxUO83Rjf0HP7Sk1DtXj6j1EwkQNZrHAg2XPWlq62oqEhYvONq5pkC2Y9oPljWToLmQ==",
		},
		"zone.js": {
			Resolved:  "https://registry.npmjs.org/zone.js/-/zone.js-0.11.8.tgz",
			Integrity: "sha512-82bctBg2hKcEJ21humWIkXRlLBBmrc3nN7DFh5LGGhcyycO2S7FN8NmdvlcKaGFDNVL4/9kFLmwmInTavdJERA==",
		},
	}
	rxjs := pkg.Package{
		Name:         "rxjs",
		Version:      "7.5.0",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/rxjs@7.5.0",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
	}
	testApp := pkg.Package{
		Name:         "test-app",
		Version:      "0.0.0",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/test-app@0.0.0",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
	}
	tslib := pkg.Package{
		Name:         "tslib",
		Version:      "2.6.2",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/tslib@2.6.2",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
	}
	typescript := pkg.Package{
		Name:         "typescript",
		Version:      "4.7.4",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/typescript@4.7.4",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
	}
	zonejs := pkg.Package{
		Name:         "zone.js",
		Version:      "0.11.8",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/zone.js@0.11.8",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
	}

	l := []*pkg.Package{
		&rxjs,
		&testApp,
		&tslib,
		&typescript,
		&zonejs,
	}

	var expectedPkgs []pkg.Package
	for i := range l {
		if metadata {
			l[i].Metadata = metadataMap[l[i].Name]
			expectedPkgs = append(expectedPkgs, *l[i])
		} else {
			expectedPkgs = append(expectedPkgs, *l[i])
		}
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: rxjs,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: tslib,
			To:   rxjs,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: tslib,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: tslib,
			To:   zonejs,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: typescript,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: zonejs,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
	}

	return expectedPkgs, expectedRelationships
}

func expectedPackagesAndRelationshipsPnpmLock(locationSet file.LocationSet, metadata bool) ([]pkg.Package, []artifact.Relationship) {
	metadataMap := map[string]pkg.NpmPackageLockJSONMetadata{
		"rxjs": {
			Resolved:  "https://registry.npmjs.org/rxjs/-/rxjs-7.5.7.tgz",
			Integrity: "sha512-z9MzKh/UcOqB3i20H6rtrlaE/CgjLOvheWK/9ILrbhROGTweAi1BaFsTT9FbwZi5Trr1qNRs+MXkhmR06awzQA==",
		},
		"test-app": {
			Resolved:  "",
			Integrity: "",
		},
		"tslib": {
			Resolved:  "https://registry.npmjs.org/tslib/-/tslib-2.6.2.tgz",
			Integrity: "sha512-tGyy4dAjRIEwI7BzsB0lynWgOpfqjUdq91XXAlIWD2OwKBH7oCl/GZG/HT4BOHrTlPMOASlMQ7veyTqpmRcrNA==",
		},
		"typescript": {
			Resolved:  "https://registry.npmjs.org/typescript/-/typescript-4.7.4.tgz",
			Integrity: "sha512-C0WQT0gezHuw6AdY1M2jxUO83Rjf0HP7Sk1DtXj6j1EwkQNZrHAg2XPWlq62oqEhYvONq5pkC2Y9oPljWToLmQ==",
		},
		"zone.js": {
			Resolved:  "https://registry.npmjs.org/zone.js/-/zone.js-0.11.8.tgz",
			Integrity: "sha512-82bctBg2hKcEJ21humWIkXRlLBBmrc3nN7DFh5LGGhcyycO2S7FN8NmdvlcKaGFDNVL4/9kFLmwmInTavdJERA==",
		},
	}
	rxjs := pkg.Package{
		Name:         "rxjs",
		Version:      "7.5.7",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/rxjs@7.5.7",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	testApp := pkg.Package{
		Name:         "test-app",
		Version:      "0.0.0",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/test-app@0.0.0",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	tslib := pkg.Package{
		Name:         "tslib",
		Version:      "2.6.2",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/tslib@2.6.2",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	typescript := pkg.Package{
		Name:         "typescript",
		Version:      "4.7.4",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/typescript@4.7.4",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}
	zonejs := pkg.Package{
		Name:         "zone.js",
		Version:      "0.11.8",
		FoundBy:      "javascript-cataloger",
		PURL:         "pkg:npm/zone.js@0.11.8",
		Locations:    locationSet,
		Language:     pkg.JavaScript,
		Type:         pkg.NpmPkg,
		MetadataType: pkg.NpmPackageLockJSONMetadataType,
		Metadata:     pkg.NpmPackageLockJSONMetadata{},
	}

	l := []*pkg.Package{
		&rxjs,
		&testApp,
		&tslib,
		&typescript,
		&zonejs,
	}

	var expectedPkgs []pkg.Package
	for i := range l {
		if metadata {
			l[i].Metadata = metadataMap[l[i].Name]
			expectedPkgs = append(expectedPkgs, *l[i])
		} else {
			expectedPkgs = append(expectedPkgs, *l[i])
		}
	}

	expectedRelationships := []artifact.Relationship{
		{
			From: rxjs,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: tslib,
			To:   rxjs,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: tslib,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: tslib,
			To:   zonejs,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
		{
			From: zonejs,
			To:   testApp,
			Type: artifact.DependencyOfRelationship,
			Data: nil,
		},
	}

	return expectedPkgs, expectedRelationships
}

func Test_JavaScriptCataloger_PkgLock_v1(t *testing.T) {
	locationSet := file.NewLocationSet(file.NewLocation("package-lock.json"))
	expectedPkgs, expectedRelationships := expectedPackagesAndRelationshipsLockV1(locationSet, true)
	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/pkg-json-and-lock/v1").
		Expects(expectedPkgs, expectedRelationships).
		TestGroupedCataloger(t, NewJavaScriptCataloger())
}

func Test_JavaScriptCataloger_PkgLock_v2(t *testing.T) {
	locationSet := file.NewLocationSet(file.NewLocation("package-lock.json"))
	expectedPkgs, expectedRelationships := expectedPackagesAndRelationshipsLockV2(locationSet, true)
	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/pkg-json-and-lock/v2").
		Expects(expectedPkgs, expectedRelationships).
		TestGroupedCataloger(t, NewJavaScriptCataloger())
}

func Test_JavaScriptCataloger_PkgLock_v3(t *testing.T) {
	locationSet := file.NewLocationSet(file.NewLocation("package-lock.json"))
	expectedPkgs, expectedRelationships := expectedPackagesAndRelationshipsLockV3(locationSet, true)
	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/pkg-json-and-lock/v3").
		Expects(expectedPkgs, expectedRelationships).
		TestGroupedCataloger(t, NewJavaScriptCataloger())
}

func Test_JavaScriptCataloger_YarnLock(t *testing.T) {
	locationSet := file.NewLocationSet(file.NewLocation("yarn.lock"))
	expectedPkgs, expectedRelationships := expectedPackagesAndRelationshipsYarnLock(locationSet, true)
	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/pkg-json-and-yarn-lock").
		Expects(expectedPkgs, expectedRelationships).
		TestGroupedCataloger(t, NewJavaScriptCataloger())
}

func Test_JavaScriptCataloger_PnpmLock(t *testing.T) {
	locationSet := file.NewLocationSet(file.NewLocation("pnpm-lock.yaml"))
	expectedPkgs, expectedRelationships := expectedPackagesAndRelationshipsPnpmLock(locationSet, false)
	pkgtest.NewCatalogTester().
		FromDirectory(t, "test-fixtures/pkg-json-and-pnpm-lock").
		Expects(expectedPkgs, expectedRelationships).
		TestGroupedCataloger(t, NewJavaScriptCataloger())
}

// TODO(noqcks): make this test work
// func Test_JavaScriptCataloger_Globs(t *testing.T) {
// 	tests := []struct {
// 		name     string
// 		fixture  string
// 		expected []string
// 	}{
// 		{
// 			name:    "obtain package lock files",
// 			fixture: "test-fixtures/pkg-json-and-lock/v1",
// 			expected: []string{
// 				"package-lock.json",
// 				"package.json",
// 			},
// 		},
// 		{
// 			name:    "obtain yarn lock files",
// 			fixture: "test-fixtures/pkg-json-and-yarn-lock",
// 			expected: []string{
// 				"yarn.lock",
// 				"package.json",
// 			},
// 		},
// 		{
// 			name:    "obtain yarn lock files",
// 			fixture: "test-fixtures/pkg-json-and-pnpm-lock",
// 			expected: []string{
// 				"pnpm-lock.yaml",
// 				"package.json",
// 			},
// 		},
// 	}

// 	for _, test := range tests {
// 		t.Run(test.name, func(t *testing.T) {
// 			pkgtest.NewCatalogTester().
// 				FromDirectory(t, test.fixture).
// 				ExpectsResolverContentQueries(test.expected).
// 				TestGroupedCataloger(t, NewJavaScriptCataloger())
// 		})
// 	}
// }
