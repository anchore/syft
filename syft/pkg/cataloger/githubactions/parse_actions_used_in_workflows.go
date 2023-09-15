package githubactions

import (
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseActionsUsedInWorkflows

type workflowDef struct {
	Jobs map[string]workflowJobDef `yaml:"jobs"`
}

type workflowJobDef struct {
	Steps []stepDef `yaml:"steps"`
}

type stepDef struct {
	Name string `yaml:"name"`
	Uses string `yaml:"uses"`
	With struct {
		Path string `yaml:"path"`
		Key  string `yaml:"key"`
	} `yaml:"with"`
}

func parseActionsUsedInWorkflows(_ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	contents, err := io.ReadAll(reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read yaml workflow file: %w", err)
	}

	var wf workflowDef
	if err = yaml.Unmarshal(contents, &wf); err != nil {
		return nil, nil, fmt.Errorf("unable to parse yaml workflow file: %w", err)
	}

	// we use a collection to help with deduplication before raising to higher level processing
	pkgs := pkg.NewCollection()

	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
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
	}

	return pkgs.Sorted(), nil, nil
}

func parseStepUsageStatement(use string) (string, string) {
	// from actions/cache@v3 get actions/cache and v3

	fields := strings.Split(use, "@")
	switch len(fields) {
	case 1:
		return use, ""
	case 2:
		return fields[0], fields[1]
	}
	return "", ""
}
