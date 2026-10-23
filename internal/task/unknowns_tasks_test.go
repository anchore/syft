package task

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
)

func Test_unknownsLabeler_archiveReasonsSurvivePackages(t *testing.T) {
	jar := file.NewCoordinates("/app.jar", "")
	p := pkg.Package{Name: "app", Locations: file.NewLocationSet(file.NewLocationFromCoordinates(jar))}
	p.SetID()
	s := &sbom.SBOM{Artifacts: sbom.Artifacts{
		Packages: pkg.NewCollection(p),
		Unknowns: map[file.Coordinates][]string{jar: {
			formatUnknown("archive cataloged from part of its contents: too big", ArchiveCatalogerTaskName),
			formatUnknown("unable to read manifest", "java-archive-cataloger"),
		}},
	}}

	unknownsLabelerTask{cataloging.UnknownsConfig{RemoveWhenPackagesDefined: true}}.finalize(file.NewMockResolverForPaths(), s)

	assert.Equal(t, []string{formatUnknown("archive cataloged from part of its contents: too big", ArchiveCatalogerTaskName)}, s.Artifacts.Unknowns[jar],
		"a package describing the archive explains a parse failure, not contents left out")
}

func Test_unknownsLabeler_ownedFilesAreWithinTheOwnersContainer(t *testing.T) {
	atRoot := file.NewCoordinates("/usr/bin/foo", "")
	inArchive := file.Coordinates{RealPath: "/rootfs.tar", FullPath: "/rootfs.tar!/usr/bin/foo"}
	owner := func(at file.Coordinates) pkg.Package {
		p := pkg.Package{
			Name:      "owner",
			Type:      pkg.RpmPkg,
			Locations: file.NewLocationSet(file.NewLocationFromCoordinates(at)),
			Metadata:  pkg.RpmDBEntry{Files: []pkg.RpmFileRecord{{Path: "/usr/bin/foo"}}},
		}
		p.SetID()
		return p
	}

	tests := []struct {
		name       string
		owner      file.Coordinates
		referenced file.Coordinates
	}{
		{name: "an owner at the scan root", owner: file.NewCoordinates("/var/lib/rpm/Packages", ""), referenced: atRoot},
		{name: "an owner inside an archive", owner: file.Coordinates{RealPath: "/rootfs.tar", FullPath: "/rootfs.tar!/var/lib/rpm/Packages"}, referenced: inArchive},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &sbom.SBOM{Artifacts: sbom.Artifacts{
				Packages:    pkg.NewCollection(owner(tt.owner)),
				Executables: map[file.Coordinates]file.Executable{atRoot: {}, inArchive: {}},
			}}

			unknownsLabelerTask{cataloging.UnknownsConfig{IncludeExecutablesWithoutPackages: true}}.finalize(file.NewMockResolverForPaths("/usr/bin/foo"), s)

			for _, exe := range []file.Coordinates{atRoot, inArchive} {
				assert.Equal(t, exe != tt.referenced, len(s.Artifacts.Unknowns[exe]) > 0, exe.FullNestedPath())
			}
		})
	}
}
