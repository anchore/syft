package githubactions

import (
	"context"
	"fmt"
	"io"
	"regexp"

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
	Uses        string    `yaml:"uses"`
	UsesComment string    `yaml:"-"`
	Steps       []stepDef `yaml:"steps"`
}

type stepDef struct {
	Name        string `yaml:"name"`
	Uses        string `yaml:"uses"`
	UsesComment string `yaml:"-"`
	With        struct {
		Path string `yaml:"path"`
		Key  string `yaml:"key"`
	} `yaml:"with"`
}

func parseWorkflowForWorkflowUsage(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	contents, errs := io.ReadAll(reader)
	if errs != nil {
		return nil, nil, fmt.Errorf("unable to read yaml workflow file: %w", errs)
	}

	// parse the yaml file into a generic node to preserve comments
	var node yaml.Node
	if errs = yaml.Unmarshal(contents, &node); errs != nil {
		return nil, nil, fmt.Errorf("unable to parse yaml workflow file: %w", errs)
	}

	// unmarshal the node into a workflowDef struct
	var wf workflowDef
	if errs = node.Decode(&wf); errs != nil {
		return nil, nil, fmt.Errorf("unable to decode workflow: %w", errs)
	}

	attachUsageComments(&node, &wf)

	// we use a collection to help with deduplication before raising to higher level processing
	pkgs := pkg.NewCollection()

	for _, job := range wf.Jobs {
		if job.Uses != "" {
			p, err := newPackageFromUsageStatement(job.Uses, job.UsesComment, reader.Location)
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

	// parse the yaml file into a generic node to preserve comments
	var node yaml.Node
	if errs = yaml.Unmarshal(contents, &node); errs != nil {
		return nil, nil, fmt.Errorf("unable to parse yaml workflow file: %w", errs)
	}

	// unmarshal the node into a workflowDef struct
	var wf workflowDef
	if errs = node.Decode(&wf); errs != nil {
		return nil, nil, fmt.Errorf("unable to decode workflow: %w", errs)
	}

	attachUsageComments(&node, &wf)

	// we use a collection to help with deduplication before raising to higher level processing
	pkgs := pkg.NewCollection()

	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "" {
				continue
			}
			p, err := newPackageFromUsageStatement(step.Uses, step.UsesComment, reader.Location)
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

// attachUsageComments traverses the yaml node tree and attaches usage comments to the workflowDef job strcuts and step structs.
// This is a best-effort approach to attach comments to the correct job or step.
func attachUsageComments(node *yaml.Node, wf *workflowDef) {
	// for a document node, process its content (usually a single mapping node)
	if node.Kind == yaml.DocumentNode && len(node.Content) > 0 {
		processNode(node.Content[0], wf, nil, nil, nil)
	} else {
		processNode(node, wf, nil, nil, nil)
	}
}

func processNode(node *yaml.Node, wf *workflowDef, currentJob *string, currentStep *int, inJobsSection *bool) {
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i < len(node.Content); i += 2 {
			key := node.Content[i]
			value := node.Content[i+1]

			// track if we're in the jobs section...
			if key.Value == "jobs" && inJobsSection == nil {
				inJobs := true
				inJobsSection = &inJobs
				processNode(value, wf, nil, nil, inJobsSection)
				continue
			}

			// if we're in jobs section, and this is a job key...
			if inJobsSection != nil && *inJobsSection && currentJob == nil {
				job := key.Value
				currentJob = &job
				processNode(value, wf, currentJob, nil, inJobsSection)
				currentJob = nil
				continue
			}

			// if this is a "uses" key...
			if key.Value == "uses" {
				processUsesNode(value, wf, currentJob, currentStep)
			}

			// if this is a "steps" key inside a job...
			if key.Value == "steps" && currentJob != nil {
				for j, stepNode := range value.Content {
					stepIndex := j
					processNode(stepNode, wf, currentJob, &stepIndex, inJobsSection)
				}
				continue
			}

			processNode(key, wf, currentJob, currentStep, inJobsSection)
			processNode(value, wf, currentJob, currentStep, inJobsSection)
		}

	case yaml.SequenceNode:
		for i, item := range node.Content {
			idx := i
			processNode(item, wf, currentJob, &idx, inJobsSection)
		}
	}
}

func processUsesNode(node *yaml.Node, wf *workflowDef, currentJob *string, currentStep *int) {
	if node.Kind != yaml.ScalarNode {
		return
	}

	comment := node.LineComment
	if comment == "" {
		comment = node.HeadComment
	}
	if comment == "" {
		comment = node.FootComment
	}

	if comment != "" {
		versionRegex := regexp.MustCompile(`v?\d+(\.\d+)*`)
		versionMatch := versionRegex.FindString(comment)

		if versionMatch != "" {
			if currentJob != nil && currentStep == nil {
				// this is a job level "uses"
				if job, ok := wf.Jobs[*currentJob]; ok {
					job.UsesComment = versionMatch
					wf.Jobs[*currentJob] = job
				}
			} else if currentJob != nil && currentStep != nil {
				// this is a step level "uses"
				if job, ok := wf.Jobs[*currentJob]; ok {
					if *currentStep < len(job.Steps) {
						job.Steps[*currentStep].UsesComment = versionMatch
						wf.Jobs[*currentJob] = job
					}
				}
			}
		}
	}
}
