package githubactions

import (
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseActionsUsedInWorkflows

type compositeActionDef struct {
	Runs compositeActionRunsDef `yaml:"runs"`
}

type compositeActionRunsDef struct {
	Steps []stepDef `yaml:"steps"`
}

func parseActionsUsedInCompositeActions(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read yaml composite action file: %w", err)
	}

	var ca compositeActionDef
	if err = yaml.Unmarshal(contents, &ca); err != nil {
		return nil, nil, fmt.Errorf("unable to parse yaml composite action file: %w", err)
	}

	// we use a collection to help with deduplication before raising to higher level processing
	pkgs := pkg.NewCollection()

	for _, step := range ca.Runs.Steps {
		if step.Uses == "" {
			continue
		}

		name, version := parseStepUsageStatement(step.Uses)

		if name == "" {
			log.WithFields("file", reader.Location.RealPath, "statement", step.Uses).Trace("unable to parse github action usage statement")
			continue
		}

		p := newGithubActionPackageUsage(name, version, reader.Location)
		if p != nil {
			pkgs.Add(*p)
		}
	}

	return pkgs.Sorted(), nil, nil
}
