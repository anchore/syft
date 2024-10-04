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
	"github.com/anchore/syft/internal/relationship"
	"github.com/anchore/syft/internal/sbomsync"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cataloging"
	"github.com/anchore/syft/syft/cataloging/pkgcataloging"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	cpeutils "github.com/anchore/syft/syft/pkg/cataloger/common/cpe"
)

type packageTaskFactory func(cfg CatalogingFactoryConfig) Task

type PackageTaskFactories []packageTaskFactory

type CatalogingFactoryConfig struct {
	ComplianceConfig     cataloging.ComplianceConfig
	SearchConfig         cataloging.SearchConfig
	RelationshipsConfig  cataloging.RelationshipsConfig
	DataGenerationConfig cataloging.DataGenerationConfig
	PackagesConfig       pkgcataloging.Config
}

func DefaultCatalogingFactoryConfig() CatalogingFactoryConfig {
	return CatalogingFactoryConfig{
		ComplianceConfig:     cataloging.DefaultComplianceConfig(),
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

		log.WithFields("cataloger", catalogerName).Debugf("discovered %d packages", len(pkgs))

		pkgs, relationships = finalizePkgCatalogerResults(cfg, resolver, catalogerName, pkgs, relationships)

		pkgs, relationships = applyCompliance(cfg.ComplianceConfig, pkgs, relationships)

		sbom.AddPackages(pkgs...)
		sbom.AddRelationships(relationships...)
		t.Add(int64(len(pkgs)))

		t.SetCompleted()
		log.WithFields("name", catalogerName).Trace("package cataloger completed")

		return err
	}
	tags = append(tags, pkgcataloging.PackageTag)

	return NewTask(c.Name(), fn, tags...)
}

func finalizePkgCatalogerResults(cfg CatalogingFactoryConfig, resolver file.PathResolver, catalogerName string, pkgs []pkg.Package, relationships []artifact.Relationship) ([]pkg.Package, []artifact.Relationship) {
	for i, p := range pkgs {
		if p.FoundBy == "" {
			p.FoundBy = catalogerName
		}

		if cfg.DataGenerationConfig.GenerateCPEs && !hasAuthoritativeCPE(p.CPEs) {
			// generate CPEs (note: this is excluded from package ID, so is safe to mutate)
			// we might have binary classified CPE already with the package so we want to append here
			dictionaryCPEs, ok := cpeutils.DictionaryFind(p)
			if ok {
				log.Tracef("used CPE dictionary to find CPEs for %s package %q: %s", p.Type, p.Name, dictionaryCPEs)
				p.CPEs = append(p.CPEs, dictionaryCPEs...)
			} else {
				p.CPEs = append(p.CPEs, cpeutils.Generate(p)...)
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
				log.Warnf("unable to create any package-file relationships for package name=%q type=%q: %v", p.Name, p.Type, err)
			} else {
				relationships = append(relationships, owningRelationships...)
			}
		}

		pkgs[i] = p
	}
	return pkgs, relationships
}

type packageReplacement struct {
	original artifact.ID
	pkg      pkg.Package
}

func applyCompliance(cfg cataloging.ComplianceConfig, pkgs []pkg.Package, relationships []artifact.Relationship) ([]pkg.Package, []artifact.Relationship) {
	remainingPkgs, droppedPkgs, replacements := filterNonCompliantPackages(pkgs, cfg)

	relIdx := relationship.NewIndex(relationships...)
	for _, p := range droppedPkgs {
		relIdx.Remove(p.ID())
	}

	for _, replacement := range replacements {
		relIdx.Replace(replacement.original, replacement.pkg)
	}

	return remainingPkgs, relIdx.All()
}

func filterNonCompliantPackages(pkgs []pkg.Package, cfg cataloging.ComplianceConfig) ([]pkg.Package, []pkg.Package, []packageReplacement) {
	var remainingPkgs, droppedPkgs []pkg.Package
	var replacements []packageReplacement
	for _, p := range pkgs {
		keep, replacement := applyComplianceRules(&p, cfg)
		if keep {
			remainingPkgs = append(remainingPkgs, p)
		} else {
			droppedPkgs = append(droppedPkgs, p)
		}
		if replacement != nil {
			replacements = append(replacements, *replacement)
		}
	}

	return remainingPkgs, droppedPkgs, replacements
}

func applyComplianceRules(p *pkg.Package, cfg cataloging.ComplianceConfig) (bool, *packageReplacement) {
	var drop bool
	var replacement *packageReplacement

	applyComplianceRule := func(value, fieldName string, action cataloging.ComplianceAction) bool {
		if strings.TrimSpace(value) != "" {
			return false
		}

		loc := "unknown"
		locs := p.Locations.ToSlice()
		if len(locs) > 0 {
			loc = locs[0].Path()
		}
		switch action {
		case cataloging.ComplianceActionDrop:
			log.WithFields("pkg", p.String(), "location", loc).Debugf("package with missing %s, dropping", fieldName)
			drop = true

		case cataloging.ComplianceActionStub:
			log.WithFields("pkg", p.String(), "location", loc).Debugf("package with missing %s, stubbing with default value", fieldName)
			return true

		case cataloging.ComplianceActionKeep:
			log.WithFields("pkg", p.String(), "location", loc).Tracef("package with missing %s, taking no action", fieldName)
		}
		return false
	}

	ogID := p.ID()

	if applyComplianceRule(p.Name, "name", cfg.MissingName) {
		p.Name = cataloging.UnknownStubValue
		p.SetID()
	}

	if applyComplianceRule(p.Version, "version", cfg.MissingVersion) {
		p.Version = cataloging.UnknownStubValue
		p.SetID()
	}

	newID := p.ID()
	if newID != ogID {
		replacement = &packageReplacement{
			original: ogID,
			pkg:      *p,
		}
	}

	return !drop, replacement
}

func hasAuthoritativeCPE(cpes []cpe.CPE) bool {
	for _, c := range cpes {
		if c.Source != cpe.GeneratedSource {
			return true
		}
	}
	return false
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
