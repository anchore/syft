package cpp

import (
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

const defaultRepo = "https://github.com/microsoft/vcpkg"

// this is the default registry for vcpkg. it is the default "builtin" registry if a builtin one isn't specified 
var defaultRegistry = pkg.VcpkgRegistryEntry{
	Baseline: "master",
	Kind: pkg.Git,
	Repository: defaultRepo,
}
var defaultLock = vcpkg.VcpkgLockEntry{
	Repo: defaultRepo, 
	// supposed to be the latest commit sha of the repo at build time. If no vcpkg-lock.json file is found, default to master. 
	Head: "master",
}

// parser is for vcpkg in "Manifest" mode. This is opposed to "Classic" mode which or is more akin to a system package manager. (https://learn.microsoft.com/en-us/vcpkg/concepts/classic-mode)
func (vc *vcpkgCataloger) parseVcpkgmanifest(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	lockFile, err := findLockFile(resolver)
	if err != nil {
		return nil, nil, fmt.Errorf("something went wrong parsing vcpkg-lock.json file: %w", err)
	}
	conf, err := findVcpkgConfig(resolver)
	if err != nil {
		return nil, nil, fmt.Errorf("something went wrong parsing vcpkg-configuration.json file: %w", err)
	}

	// lock file preferred for determining what Baseline commit hash. (baseline could be a branch name which can change)
	for _, lockRec := range lockFile.Records {
		if conf.DefaultRegistry != nil && conf.DefaultRegistry.Repository == lockRec.Repo {
			conf.DefaultRegistry.Baseline = lockRec.Head
		}
		for ind, reg := range conf.Registries {
			if lockRec.Repo == reg.Repository {
				conf.Registries[ind].Baseline = lockRec.Head
			}
		}
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
		return nil, nil, fmt.Errorf("Could not get overlay port manifests: %w", err)
	}
	vcpkgs = append(vcpkgs, overlayVcpkgs...)
	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	for _, parentVcpkg := range vcpkgs {
		triplet := identifyTripletForDep(resolver, parentVcpkg.Name)
		parentMan := parentVcpkg.BuildManifest(nil, triplet)
		pPkg := newVcpkgPackage(ctx, parentMan, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)) 
		pkgs = append(
			pkgs,
			pPkg)

		// builtin by default is the git repo https://github.com/microsoft/vcpkg pointed to by VCPKG_ROOT env variable.
		if parentVcpkg.BuiltinBaseline != "" {
			if conf.DefaultRegistry != nil {
				conf.DefaultRegistry.Baseline = parentVcpkg.BuiltinBaseline
			}
			for ind, reg := range conf.Registries {
				if reg.Kind == pkg.Builtin {
					conf.Registries[ind].Baseline = parentVcpkg.BuiltinBaseline 
				}
			}
		}
		r := vcpkg.NewResolver(
			conf,
			vc.allowGitClone,
		)
		for _, dep := range parentVcpkg.Dependencies {
			cMans, fetchErr := r.FindManifests(dep, true, triplet, toplevelVcpkg.Overrides, parentMan)
			if fetchErr != nil {
				return nil, nil, fmt.Errorf("failed to fetch vcpkg.json file: %w", fetchErr)
			}
			for _, c := range cMans {
				if c.Child != nil && !hasBeenOverlayed(c.Child.Name, overlayVcpkgs) {
					c.Child.Triplet = identifyTripletForDep(resolver, c.Child.Name)
					cPkg := newVcpkgPackage(ctx, c.Child, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
					if c.Parent != nil {
						c.Parent.Triplet = identifyTripletForDep(resolver, c.Parent.Name)
						pPkg := newVcpkgPackage(ctx, c.Parent, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
						rship := artifact.Relationship{
							From: pPkg,
							To: cPkg,
							Type: artifact.DependencyOfRelationship,
						}
						relationships = append(
							relationships,
							rship)
					}
					pkgs = append(
						pkgs,
						cPkg)
				}
			}
		}
	}
	pkg.Sort(pkgs)
	return pkgs, relationships, nil
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
			manCont, err := resolver.FileContentsByLocation(loc)
			if err != nil {
				return nil, err
			}
			defer internal.CloseAndLogError(manCont, locs[0].RealPath)
			manBytes, err := io.ReadAll(manCont)
			var man vcpkg.Vcpkg
			err = json.Unmarshal(manBytes, &man)
			if err != nil {
				return nil, err
			}
			manifests = append(manifests, man)
		}
	}
	return manifests, nil
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
func identifyTripletForDep(resolver file.Resolver, name string) string {
	locs, err := resolver.FilesByGlob("**/build/vcpkg_installed/*/share/" + name + "/copyright")
	if err != nil {
		return ""
	}
	if len(locs) != 0 {
		path := locs[0].Path()
		return strings.TrimPrefix(strings.TrimSuffix(path, "/share/" + name + "/copyright"), "/build/vcpkg_installed/")
	}
	return ""
}

// needed to know what vcpkg registries to use for what packages when looking for manifest files 
func findVcpkgConfig(resolver file.Resolver) (*vcpkg.VcpkgConfig, error) {
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

		var vcpkgConf vcpkg.VcpkgConfig
		err = json.Unmarshal(cfgBytes, &vcpkgConf)
		if err != nil {
			return nil, err
		}
		if vcpkgConf.DefaultRegistry == nil {
			vcpkgConf.DefaultRegistry = &defaultRegistry
		}
		return &vcpkgConf, err
	} else {
		return &vcpkg.VcpkgConfig{
			DefaultRegistry: &defaultRegistry,
		}, nil 
	}
}

// Gives the git commit hash(es) for the repo(s) listed in the vcpkg-configuration.json file
func findLockFile(resolver file.Resolver) (*vcpkg.VcpkgLock, error) {
	locs, err := resolver.FilesByGlob("**/vcpkg-lock.json")
	if err != nil || len(locs) == 0 {
		return &vcpkg.VcpkgLock{
			Records: []vcpkg.VcpkgLockEntry{defaultLock},
		}, nil
	}
	lockContents, err := resolver.FileContentsByLocation(locs[0])
	if err != nil || lockContents == nil {
		return nil, err
	}
	defer internal.CloseAndLogError(lockContents, locs[0].RealPath)
	lockBytes, err := io.ReadAll(lockContents)

	var lockFile any
	json.Unmarshal(lockBytes, &lockFile)

	var lockRecords []vcpkg.VcpkgLockEntry
	for k, v := range lockFile.(map[string]any) {
		switch t := v.(type) {
		case map[string]any:
			for _, v2 := range t {
				switch t2 := v2.(type) {
				case string:
					lockRecords = append(lockRecords, vcpkg.VcpkgLockEntry{
						Repo: k,
						Head: t2,
					})
				}
			}
		}
	}
	return &vcpkg.VcpkgLock{
		Records: lockRecords,
	}, nil 
}

