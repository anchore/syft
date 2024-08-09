package githubactions

import (
	"context"
	"fmt"
	"io"

	"gopkg.in/yaml.v3"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var (
	_ generic.Parser = parseWorkflowForActionUsage
	_ generic.Parser = parseWorkflowForWorkflowUsage
)

type workflowDef struct {
	Jobs map[string]workflowJobDef `yaml:"jobs"`
}

type workflowJobDef struct {
	Uses  string    `yaml:"uses"`
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

func parseWorkflowForWorkflowUsage(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	contents, errs := io.ReadAll(reader)
	if errs != nil {
		return nil, nil, fmt.Errorf("unable to read yaml workflow file: %w", errs)
	}

	var wf workflowDef
	if errs = yaml.Unmarshal(contents, &wf); errs != nil {
		return nil, nil, fmt.Errorf("unable to parse yaml workflow file: %w", errs)
	}

	// we use a collection to help with deduplication before raising to higher level processing
	pkgs := pkg.NewCollection()

	for _, job := range wf.Jobs {
		if job.Uses != "" {
			p, err := newPackageFromUsageStatement(job.Uses, reader.Location)
			if err != nil {
				errs = unknown.Append(errs, reader, err)
			}
			if p != nil {
				pkgs.Add(*p)
			}
		}
	}

	return pkgs.Sorted(), nil, errs
}

func parseWorkflowForActionUsage(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	contents, errs := io.ReadAll(reader)
	if errs != nil {
		return nil, nil, fmt.Errorf("unable to read yaml workflow file: %w", errs)
	}

	var wf workflowDef
	if errs = yaml.Unmarshal(contents, &wf); errs != nil {
		return nil, nil, fmt.Errorf("unable to parse yaml workflow file: %w", errs)
	}

	// we use a collection to help with deduplication before raising to higher level processing
	pkgs := pkg.NewCollection()

	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}
			p, err := newPackageFromUsageStatement(step.Uses, reader.Location)
			if err != nil {
				errs = unknown.Append(errs, reader, err)
			}
			if p != nil {
				pkgs.Add(*p)
			}
		}
	}

	return pkgs.Sorted(), nil, errs
}
