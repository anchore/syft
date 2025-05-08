package redhat

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/assert"
	_ "modernc.org/sqlite"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/internal/pkgtest"
)

func Test_DBCataloger(t *testing.T) {

	dbLocation := file.NewLocation("/var/lib/rpm/rpmdb.sqlite")
	locations := file.NewLocationSet(dbLocation.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))

	basePkg := pkg.Package{
		Name:      "basesystem",
		Version:   "11-13.el9",
		Type:      pkg.RpmPkg,
		Locations: locations,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicenseFromLocations("Public Domain", dbLocation)),
		FoundBy:   "rpm-db-cataloger",
		PURL:      "pkg:rpm/basesystem@11-13.el9?arch=noarch&upstream=basesystem-11-13.el9.src.rpm",
		Metadata: pkg.RpmDBEntry{
			Name:      "basesystem",
			Version:   "11",
			Arch:      "noarch",
			Release:   "13.el9",
			SourceRpm: "basesystem-11-13.el9.src.rpm",
			Size:      0,
			Vendor:    "Rocky Enterprise Software Foundation",
			Provides:  []string{"basesystem"},
			Requires: []string{
				"filesystem",
				"rpmlib(CompressedFileNames)",
				"rpmlib(FileDigests)",
				"rpmlib(PayloadFilesHavePrefix)",
				"rpmlib(PayloadIsZstd)",
				"setup",
			},
			ModularityLabel: strRef(""),
		},
	}
	basePkg.SetID()

	bashPkg := pkg.Package{
		Name:      "bash",
		Version:   "5.1.8-6.el9_1",
		Type:      pkg.RpmPkg,
		Locations: locations,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicenseFromLocations("GPLv3+", dbLocation)),
		FoundBy:   "rpm-db-cataloger",
		PURL:      "pkg:rpm/bash@5.1.8-6.el9_1?arch=x86_64&upstream=bash-5.1.8-6.el9_1.src.rpm",
		Metadata: pkg.RpmDBEntry{
			Name:            "bash",
			Version:         "5.1.8",
			Arch:            "x86_64",
			Release:         "6.el9_1",
			SourceRpm:       "bash-5.1.8-6.el9_1.src.rpm",
			Size:            7738634,
			ModularityLabel: strRef(""),
			Vendor:          "Rocky Enterprise Software Foundation",
			Provides: []string{
				"/bin/bash",
				"/bin/sh",
				"bash",
				"bash(x86-64)",
				"config(bash)",
			},
			Requires: []string{
				"/usr/bin/sh",
				"config(bash)",
				"filesystem",
				"libc.so.6()(64bit)",
				"libc.so.6(GLIBC_2.11)(64bit)",
				"libc.so.6(GLIBC_2.14)(64bit)",
				"libc.so.6(GLIBC_2.15)(64bit)",
				"libc.so.6(GLIBC_2.2.5)(64bit)",
				"libc.so.6(GLIBC_2.25)(64bit)",
				"libc.so.6(GLIBC_2.3)(64bit)",
				"libc.so.6(GLIBC_2.3.4)(64bit)",
				"libc.so.6(GLIBC_2.33)(64bit)",
				"libc.so.6(GLIBC_2.34)(64bit)",
				"libc.so.6(GLIBC_2.4)(64bit)",
				"libc.so.6(GLIBC_2.8)(64bit)",
				"libtinfo.so.6()(64bit)",
				"rpmlib(BuiltinLuaScripts)",
				"rpmlib(CompressedFileNames)",
				"rpmlib(FileDigests)",
				"rpmlib(PayloadFilesHavePrefix)",
				"rpmlib(PayloadIsZstd)",
				"rtld(GNU_HASH)",
			},
		},
	}
	bashPkg.SetID()

	filesystemPkg := pkg.Package{
		Name:      "filesystem",
		Version:   "3.16-2.el9",
		Type:      pkg.RpmPkg,
		Locations: locations,
		Licenses:  pkg.NewLicenseSet(pkg.NewLicenseFromLocations("Public Domain", dbLocation)),
		FoundBy:   "rpm-db-cataloger",
		PURL:      "pkg:rpm/filesystem@3.16-2.el9?arch=x86_64&upstream=filesystem-3.16-2.el9.src.rpm",
		Metadata: pkg.RpmDBEntry{
			Name:            "filesystem",
			Version:         "3.16",
			Arch:            "x86_64",
			Release:         "2.el9",
			SourceRpm:       "filesystem-3.16-2.el9.src.rpm",
			Size:            106,
			ModularityLabel: strRef(""),
			Vendor:          "Rocky Enterprise Software Foundation",
			Provides: []string{
				"filesystem",
				"filesystem(x86-64)",
				"filesystem-afs",
			},
			Requires: []string{
				"/bin/sh",
				"rpmlib(BuiltinLuaScripts)",
				"rpmlib(CompressedFileNames)",
				"rpmlib(FileDigests)",
				"rpmlib(PayloadFilesHavePrefix)",
				"rpmlib(PayloadIsZstd)",
				"setup",
			},
		},
	}
	filesystemPkg.SetID()

	expectedPackages := []pkg.Package{basePkg, bashPkg, filesystemPkg}

	// Note that you'll see a cycle:
	//   bash --(requires)--> filesystem
	//   filesystem --(requires)--> bash
	//
	// This is not a bug!
	//
	// [root@c1a4773e8a8d /]# dnf repoquery --requires --resolve filesystem
	//   bash-0:5.1.8-9.el9.aarch64
	//   setup-0:2.13.7-10.el9.noarch
	//
	//[root@c1a4773e8a8d /]# dnf repoquery --requires --resolve bash
	//  filesystem-0:3.16-2.el9.aarch64
	//  glibc-0:2.34-100.el9.aarch64
	//  ncurses-libs-0:6.2-10.20210508.el9.aarch64

	expectedRelationships := []artifact.Relationship{
		// though this is expressible in the RPM DB (package depends on itself), we do not allow for it in the SBOM
		//{
		//	From: bashPkg,
		//	To:   bashPkg,
		//	Type: artifact.DependencyOfRelationship,
		//},
		{
			From: bashPkg,
			To:   filesystemPkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: filesystemPkg,
			To:   basePkg,
			Type: artifact.DependencyOfRelationship,
		},
		{
			From: filesystemPkg,
			To:   bashPkg,
			Type: artifact.DependencyOfRelationship,
		},
	}

	pkgtest.NewCatalogTester().
		WithImageResolver(t, "image-minimal").
		IgnoreLocationLayer().                                               // this fixture can be rebuilt, thus the layer ID will change
		WithCompareOptions(cmpopts.IgnoreFields(pkg.RpmDBEntry{}, "Files")). // this is rather long... ano not the point of the test
		Expects(expectedPackages, expectedRelationships).
		TestCataloger(t, NewDBCataloger())

}

func Test_DBCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain DB files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"usr/share/rpm/Packages",
				"usr/share/rpm/Packages.db",
				"usr/share/rpm/rpmdb.sqlite",
				"var/lib/rpm/Packages",
				"var/lib/rpm/Packages.db",
				"var/lib/rpm/rpmdb.sqlite",
				"var/lib/rpmmanifest/container-manifest-2",
				"usr/lib/sysimage/rpm/Packages",
				"usr/lib/sysimage/rpm/Packages.db",
				"usr/lib/sysimage/rpm/rpmdb.sqlite",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewDBCataloger())
		})
	}
}

func Test_RPMFileCataloger_Globs(t *testing.T) {
	tests := []struct {
		name     string
		fixture  string
		expected []string
	}{
		{
			name:    "obtain rpm files",
			fixture: "test-fixtures/glob-paths",
			expected: []string{
				"dive-0.10.0.rpm",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pkgtest.NewCatalogTester().
				FromDirectory(t, test.fixture).
				ExpectsResolverContentQueries(test.expected).
				TestCataloger(t, NewArchiveCataloger())
		})
	}
}

func Test_denySelfReferences(t *testing.T) {

	a := pkg.Package{
		Name: "a",
	}
	a.SetID()
	b := pkg.Package{
		Name: "b",
	}
	b.SetID()
	c := pkg.Package{
		Name: "c",
	}
	c.SetID()

	pkgs := []pkg.Package{a, b, c}

	tests := []struct {
		name              string
		pkgs              []pkg.Package
		rels              []artifact.Relationship
		err               error
		wantPkgs          int
		wantRelationships int
		wantErr           assert.ErrorAssertionFunc
	}{
		{
			name: "no self references",
			pkgs: pkgs,
			rels: []artifact.Relationship{
				{
					From: a,
					To:   b,
					Type: artifact.DependencyOfRelationship,
				},
			},
			wantPkgs:          3,
			wantRelationships: 1,
			wantErr:           assert.NoError,
		},
		{
			name: "remove self references",
			pkgs: pkgs,
			rels: []artifact.Relationship{
				{
					From: a,
					To:   a,
					Type: artifact.DependencyOfRelationship,
				},
				{
					From: a,
					To:   b,
					Type: artifact.DependencyOfRelationship,
				},
			},
			wantPkgs:          3,
			wantRelationships: 1,
			wantErr:           assert.NoError,
		},
		{
			name: "preserve errors",
			pkgs: pkgs,
			rels: []artifact.Relationship{
				{
					From: a,
					To:   b,
					Type: artifact.DependencyOfRelationship,
				},
			},
			err:               errors.New("stop me!"),
			wantPkgs:          3,
			wantRelationships: 1,
			wantErr:           assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}

			gotPkgs, gotRels, err := denySelfReferences(tt.pkgs, tt.rels, tt.err)

			tt.wantErr(t, err)
			assert.Len(t, gotPkgs, tt.wantPkgs)
			assert.Len(t, gotRels, tt.wantRelationships)
		})
	}
}
