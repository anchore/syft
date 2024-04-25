package task

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/scylladb/go-set/strset"

	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
)

type packageTaskFactory func(cfg CatalogingFactoryConfig) Task

type PackageTaskFactories []packageTaskFactory

type CatalogingFactoryConfig struct {
	SearchConfig         cataloging.SearchConfig
	RelationshipsConfig  cataloging.RelationshipsConfig
	DataGenerationConfig cataloging.DataGenerationConfig
	PackagesConfig       pkgcataloging.Config
}

func DefaultCatalogingFactoryConfig() CatalogingFactoryConfig {
	return CatalogingFactoryConfig{
		SearchConfig:         cataloging.DefaultSearchConfig(),
		RelationshipsConfig:  cataloging.DefaultRelationshipsConfig(),
		DataGenerationConfig: cataloging.DefaultDataGenerationConfig(),
		PackagesConfig:       pkgcataloging.DefaultConfig(),
	}
}

func newPackageTaskFactory(catalogerFactory func(CatalogingFactoryConfig) pkg.Cataloger, tags ...string) packageTaskFactory {
	return func(cfg CatalogingFactoryConfig) Task {
		return NewPackageTask(cfg, catalogerFactory(cfg), tags...)
	}
}

func newSimplePackageTaskFactory(catalogerFactory func() pkg.Cataloger, tags ...string) packageTaskFactory {
	return func(cfg CatalogingFactoryConfig) Task {
		return NewPackageTask(cfg, catalogerFactory(), tags...)
	}
}

func (f PackageTaskFactories) Tasks(cfg CatalogingFactoryConfig) ([]Task, error) {
	var allTasks []Task
	taskNames := strset.New()
	duplicateTaskNames := strset.New()
	var err error
	for _, factory := range f {
		tsk := factory(cfg)
		if tsk == nil {
			continue
		}
		tskName := tsk.Name()
		if taskNames.Has(tskName) {
			duplicateTaskNames.Add(tskName)
		}

		allTasks = append(allTasks, tsk)
		taskNames.Add(tskName)
	}
	if duplicateTaskNames.Size() > 0 {
		names := duplicateTaskNames.List()
		sort.Strings(names)
		err = fmt.Errorf("duplicate cataloger task names: %v", strings.Join(names, ", "))
	}

	return allTasks, err
}

// NewPackageTask creates a Task function for a generic pkg.Cataloger, honoring the common configuration options.
//
//nolint:funlen
func NewPackageTask(cfg CatalogingFactoryConfig, c pkg.Cataloger, tags ...string) Task {
	fn := func(ctx context.Context, resolver file.Resolver, sbom sbomsync.Builder) error {
		catalogerName := c.Name()
		log.WithFields("name", catalogerName).Trace("starting package cataloger")

		info := monitor.GenericTask{
			Title: monitor.Title{
				Default: prettyName(catalogerName),
			},
			ID:            catalogerName,
			ParentID:      monitor.PackageCatalogingTaskID,
			Context:       "",
			HideOnSuccess: true,
		}

		t := bus.StartCatalogerTask(info, -1, "")

		pkgs, relationships, err := c.Catalog(ctx, resolver)
		if err != nil {
			return fmt.Errorf("unable to catalog packages with %q: %w", c.Name(), err)
		}

		log.WithFields("cataloger", c.Name()).Debugf("discovered %d packages", len(pkgs))

		for i, p := range pkgs {
			if cfg.DataGenerationConfig.GenerateCPEs {
				// generate CPEs (note: this is excluded from package ID, so is safe to mutate)
				// we might have binary classified CPE already with the package so we want to append here
				dictionaryCPEs, ok := cpe.DictionaryFind(p)
				if ok {
					log.Tracef("used CPE dictionary to find CPEs for %s package %q: %s", p.Type, p.Name, dictionaryCPEs)
					p.CPEs = append(p.CPEs, dictionaryCPEs...)
				} else {
					p.CPEs = append(p.CPEs, cpe.Generate(p)...)
				}
			}

			// if we were not able to identify the language we have an opportunity
			// to try and get this value from the PURL. Worst case we assert that
			// we could not identify the language at either stage and set UnknownLanguage
			if p.Language == "" {
				p.Language = pkg.LanguageFromPURL(p.PURL)
			}

			if cfg.RelationshipsConfig.PackageFileOwnership {
				// create file-to-package relationships for files owned by the package
				owningRelationships, err := packageFileOwnershipRelationships(p, resolver)
				if err != nil {
					log.Warnf("unable to create any package-file relationships for package name=%q type=%q: %w", p.Name, p.Type, err)
				} else {
					relationships = append(relationships, owningRelationships...)
				}
			}

			pkgs[i] = p
		}

		sbom.AddPackages(pkgs...)
		sbom.AddRelationships(relationships...)
		t.Add(int64(len(pkgs)))

		t.SetCompleted()
		log.WithFields("name", c.Name()).Trace("package cataloger completed")

		return nil
	}
	tags = append(tags, pkgcataloging.PackageTag)

	return NewTask(c.Name(), fn, tags...)
}

func prettyName(s string) string {
	if s == "" {
		return ""
	}

	// Convert first character to uppercase
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])

	return strings.ReplaceAll(string(r), "-", " ")
}

func packageFileOwnershipRelationships(p pkg.Package, resolver file.PathResolver) ([]artifact.Relationship, error) {
	fileOwner, ok := p.Metadata.(pkg.FileOwner)
	if !ok {
		return nil, nil
	}

	locations := map[artifact.ID]file.Location{}

	for _, path := range fileOwner.OwnedFiles() {
		pathRefs, err := resolver.FilesByPath(path)
		if err != nil {
			return nil, fmt.Errorf("unable to find path for path=%q: %w", path, err)
		}

		if len(pathRefs) == 0 {
			// ideally we want to warn users about missing files from a package, however, it is very common for
			// container image authors to delete files that are not needed in order to keep image sizes small. Adding
			// a warning here would be needlessly noisy (even for popular base images).
			continue
		}

		for _, ref := range pathRefs {
			if oldRef, ok := locations[ref.Coordinates.ID()]; ok {
				log.Debugf("found path duplicate of %s", oldRef.RealPath)
			}
			locations[ref.Coordinates.ID()] = ref
		}
	}

	var relationships []artifact.Relationship
	for _, location := range locations {
		relationships = append(relationships, artifact.Relationship{
			From: p,
			To:   location.Coordinates,
			Type: artifact.ContainsRelationship,
		})
	}
	return relationships, nil
}
