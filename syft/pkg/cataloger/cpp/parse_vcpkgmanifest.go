package cpp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/cpp/internal/vcpkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseVcpkgmanifest

const defaultRepo = "https://github.com/microsoft/vcpkg"

// this is the default registry for vcpkg. it is the default "builtin" registry if a builtin one isn't specified 
var defaultRegistry = pkg.VcpkgRegistry{
	Baseline: "master",
	Kind: pkg.Git,
	Repository: defaultRepo,
}
var defaultLock = pkg.VcpkgLockRecord{
	Repo: defaultRepo, 
	// supposed to be the latest commit sha of the repo at build time. If no vcpkg-lock.json file is found, default to master. 
	Head: "master",
}

func parseVcpkgmanifest(ctx context.Context, resolver file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	lockRecords := findLockFileRecords(resolver)
	conf, err := findVcpkgConfig(resolver)
	if err != nil {
		return nil, nil, fmt.Errorf("something went wrong parsing vcpkg-configuration.json file: %w", err)
	}

	// use as the source of truth for the Baseline commit hash to use
	for _, lockRec := range lockRecords {
		if lockRec.Repo == conf.DefaultRegistry.Repository {
			conf.DefaultRegistry.Baseline = lockRec.Head
		}
		for ind, reg := range conf.Registries {
			if lockRec.Repo == reg.Repository {
				conf.Registries[ind].Baseline = lockRec.Head
			}
		}
	}

	// find full manifests for all dependencies
	var pkgs []pkg.Package
	var relationships []artifact.Relationship
	for {
		var pMan pkg.VcpkgManifest
		dec := json.NewDecoder(reader)
		if err := dec.Decode(&pMan); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, nil, fmt.Errorf("failed to parse vcpkg.json file: %w", err)
		}
		pPkg := newVcpkgPackage(ctx, pMan, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)) 
		pkgs = append(
			pkgs,
			pPkg)
		
		if pMan.BuiltinBaseline != "" {
			conf.DefaultRegistry.Baseline = pMan.BuiltinBaseline
			for ind, reg := range conf.Registries {
				if reg.Kind == pkg.Builtin {
					conf.Registries[ind].Baseline = pMan.BuiltinBaseline 
				}
			}
		}
		r := vcpkg.NewResolver(
			conf,
		)
		for _, dep := range pMan.Dependencies {
			cMans, fetchErr := r.FindManifestsInRemoteRepository(ctx, dep, true, &pMan)
			if fetchErr != nil {
				return nil, nil, fmt.Errorf("failed to fetch vcpkg.json file: %w", fetchErr)
			}
			for _, c := range cMans {
				if c.Child != nil {
					cPkg := newVcpkgPackage(ctx, *c.Child, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
					if c.Parent != nil {
						pPkg := newVcpkgPackage(ctx, *c.Parent, reader.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation))
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

func findVcpkgConfig(resolver file.Resolver) (pkg.VcpkgConfig, error) {
	loc, err := resolver.FilesByGlob("**/vcpkg-configuration.json")
	if err != nil {
		return pkg.VcpkgConfig{}, err
	}
	if len(loc) != 0 {
		cfgConf, err := resolver.FileContentsByLocation(loc[0])
		if err != nil {
			return pkg.VcpkgConfig{}, err
		}
		defer internal.CloseAndLogError(cfgConf, loc[0].RealPath)
		cfgBytes, err := io.ReadAll(cfgConf)

		var vcpkgConf pkg.VcpkgConfig
		err = json.Unmarshal(cfgBytes, &vcpkgConf)
		if err != nil {
			return pkg.VcpkgConfig{}, err
		}
		// if no Kind, default-registry wasn't defined since it is required
		if vcpkgConf.DefaultRegistry.Kind == "" {
			vcpkgConf.DefaultRegistry = defaultRegistry
		}
		return vcpkgConf, err
	} else {
		return pkg.VcpkgConfig{
			DefaultRegistry: defaultRegistry,
		}, nil 
	}
}

func findLockFileRecords(resolver file.Resolver) []pkg.VcpkgLockRecord {
	loc, err := resolver.FilesByGlob("**/vcpkg-lock.json")
	if err != nil || len(loc) == 0 {
		// may want to throw an error here if a vcpkg-lock.json file is not present
		return []pkg.VcpkgLockRecord{defaultLock}
	}
	lockContents, err := resolver.FileContentsByLocation(loc[0])
	if err != nil || lockContents == nil {
		return []pkg.VcpkgLockRecord{defaultLock}
	}
	defer internal.CloseAndLogError(lockContents, loc[0].RealPath)
	lockBytes, err := io.ReadAll(lockContents)

	var lockFile any
	json.Unmarshal(lockBytes, &lockFile)

	var lockRecords []pkg.VcpkgLockRecord
	for k, v := range lockFile.(map[string]any) {
		switch t := v.(type) {
		case map[string]any:
			for _, v2 := range t {
				switch t2 := v2.(type) {
				case string:
					lockRecords = append(lockRecords, pkg.VcpkgLockRecord{
						Repo: k,
						Head: t2,
					})
				}
			}
		}
	}
	return lockRecords 
}
