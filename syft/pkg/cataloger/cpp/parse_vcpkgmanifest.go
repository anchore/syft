package cpp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/cpp/internal/vcpkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

type vcpkgCataloger struct {
	allowGitClone bool
}

func newVcpkgCataloger(allowGitClone bool) *vcpkgCataloger {
	return &vcpkgCataloger{
		allowGitClone: allowGitClone,
	}
}

// parser is for vcpkg in "Manifest" mode. This is opposed to "Classic" mode which or is more akin to a system package manager. (https://learn.microsoft.com/en-us/vcpkg/concepts/classic-mode)
func (v *vcpkgCataloger) parseVcpkgManifest(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	conf, err := findVcpkgConfig(resolver)
	if err != nil {
		return nil, nil, fmt.Errorf("something went wrong parsing vcpkg-configuration.json file: %w", err)
	}

	var toplevelVcpkg vcpkg.Vcpkg
	dec := json.NewDecoder(reader)
	err = dec.Decode(&toplevelVcpkg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse vcpkg.json file: %w", err)
	}

	var vcpkgs []vcpkg.Vcpkg
	vcpkgs = append(vcpkgs, toplevelVcpkg)
	overlayVcpkgs, err := findOverlayManifests(resolver, conf.OverlayPorts)
	if err != nil {
		return nil, nil, fmt.Errorf("could not get overlay port manifests: %w", err)
	}
	vcpkgs = append(vcpkgs, overlayVcpkgs...)
	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	for _, parentVcpkg := range vcpkgs {
		triplet := identifyTripletForVcpkg(resolver, toplevelVcpkg.Name, parentVcpkg.Name)
		parentMan := parentVcpkg.BuildManifest(nil, triplet)
		pPkg := newVcpkgPackage(ctx, parentMan, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
		pkgs = append(
			pkgs,
			pPkg)

		r := vcpkg.NewResolver(
			conf,
			v.allowGitClone,
		)
		for _, dep := range parentVcpkg.Dependencies {
			cMans, fetchErr := r.FindManifests(dep, true, triplet, toplevelVcpkg.BuiltinBaseline, toplevelVcpkg.Overrides, parentMan)
			if fetchErr != nil {
				return nil, nil, fmt.Errorf("failed to fetch vcpkg.json file: %w", fetchErr)
			}
			pkgs, relationships = appendPkgsAndRelationships(ctx, toplevelVcpkg, cMans, overlayVcpkgs, resolver, reader, relationships, pkgs)
		}
	}
	pkg.Sort(pkgs)
	return pkgs, relationships, nil
}

func appendPkgsAndRelationships(ctx context.Context, toplevelVcpkg vcpkg.Vcpkg, cMans []vcpkg.ManifestNode, overlayVcpkgs []vcpkg.Vcpkg, resolver file.Resolver, reader file.LocationReadCloser, relationships []artifact.Relationship, pkgs []pkg.Package) ([]pkg.Package, []artifact.Relationship) {
	p := pkgs
	r := relationships
	for _, c := range cMans {
		if c.Child != nil && !hasBeenOverlayed(c.Child.Name, overlayVcpkgs) {
			c.Child.Triplet = identifyTripletForVcpkg(resolver, toplevelVcpkg.Name, c.Child.Name)
			cPkg := newVcpkgPackage(ctx, c.Child, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
			if c.Parent != nil {
				c.Parent.Triplet = identifyTripletForVcpkg(resolver, toplevelVcpkg.Name, c.Parent.Name)
				pPkg := newVcpkgPackage(ctx, c.Parent, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
				pPkg.FoundBy = "vcpkg-manifest-cataloger"
				cPkg.FoundBy = "vcpkg-manifest-cataloger"
				rship := artifact.Relationship{
					From: pPkg,
					To:   cPkg,
					Type: artifact.DependencyOfRelationship,
				}
				r = append(
					r,
					rship)
			}
			p = append(
				p,
				cPkg)
		}
	}
	return p, r
}

// These are to be used in place of dependencies with the same name
func findOverlayManifests(resolver file.Resolver, overlayPorts []string) ([]vcpkg.Vcpkg, error) {
	var manifests []vcpkg.Vcpkg
	for _, op := range overlayPorts {
		// overlay port path is relative to location of vcpkg-configuration.json file
		locs, err := resolver.FilesByGlob(op + "/**/vcpkg.json")
		if err != nil {
			return nil, err
		}
		for _, loc := range locs {
			man, err := findManAtLoc(loc, resolver)
			if err != nil {
				return nil, err
			}
			manifests = append(manifests, *man)
		}
	}
	return manifests, nil
}

func findManAtLoc(loc file.Location, resolver file.Resolver) (*vcpkg.Vcpkg, error) {
	manCont, err := resolver.FileContentsByLocation(loc)
	if err != nil {
		return nil, err
	}
	defer internal.CloseAndLogError(manCont, loc.RealPath)
	manBytes, err := io.ReadAll(manCont)
	if err != nil {
		return nil, err
	}
	var man vcpkg.Vcpkg
	err = json.Unmarshal(manBytes, &man)
	if err != nil {
		return nil, err
	}
	return &man, nil
}

// check to see if a package is not going to get pulled in because it's apart of the overlay-ports in vcpkg-configuration.json file
func hasBeenOverlayed(pkgName string, overlayMans []vcpkg.Vcpkg) bool {
	for _, om := range overlayMans {
		if om.Name == pkgName {
			return true
		}
	}
	return false
}

// capture target triplet of the build to be added to metadata. https://learn.microsoft.com/en-us/vcpkg/concepts/triplets
func identifyTripletForVcpkg(resolver file.Resolver, toplevel, name string) string {
	var locs []file.Location
	var err error
	if toplevel == name {
		locs, err = resolver.FilesByGlob("**/build/CMakeCache.txt")
		if err != nil {
			return ""
		}
		if len(locs) != 0 {
			reader, err := resolver.FileContentsByLocation(locs[0])
			if err != nil {
				return ""
			}
			defer internal.CloseAndLogError(reader, locs[0].RealPath)
			scanner := bufio.NewScanner(reader)
			targetTripPrefix := "VCPKG_TARGET_TRIPLET:STRING="
			for scanner.Scan() {
				line := scanner.Text()
				if after, ok := strings.CutPrefix(line, targetTripPrefix); ok {
					return after
				}
			}
		}
	} else {
		locs, err = resolver.FilesByGlob("**/build/vcpkg_installed/*/share/" + name + "/copyright")
		if err != nil {
			return ""
		}
		if len(locs) != 0 {
			path := locs[0].Path()
			return strings.TrimPrefix(strings.TrimSuffix(path, "/share/"+name+"/copyright"), "build/vcpkg_installed/")
		}
	}
	return ""
}

// needed to know what vcpkg registries to use for what packages when looking for manifest files
func findVcpkgConfig(resolver file.Resolver) (*vcpkg.Config, error) {
	locs, err := resolver.FilesByGlob("**/vcpkg-configuration.json")
	if err != nil {
		return nil, err
	}
	if len(locs) != 0 {
		cfgCont, err := resolver.FileContentsByLocation(locs[0])
		if err != nil {
			return nil, err
		}
		defer internal.CloseAndLogError(cfgCont, locs[0].RealPath)
		cfgBytes, err := io.ReadAll(cfgCont)
		if err != nil {
			return nil, err
		}
		var vcpkgConf vcpkg.Config
		err = json.Unmarshal(cfgBytes, &vcpkgConf)
		if err != nil {
			return nil, err
		}
		return &vcpkgConf, err
	}
	return &vcpkg.Config{}, nil
}
