package githubactions

import (
	"context"
	"fmt"
	"io"

	"go.yaml.in/yaml/v3"

	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
)

var _ generic.Parser = parseCompositeActionForActionUsage

type compositeActionDef struct {
	Runs compositeActionRunsDef `yaml:"runs"`
}

type compositeActionRunsDef struct {
	Steps []stepDef `yaml:"steps"`
}

func parseCompositeActionForActionUsage(_ context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	contents, errs := io.ReadAll(reader)
	if errs != nil {
		return nil, nil, fmt.Errorf("unable to read yaml composite action file: %w", errs)
	}

	var node yaml.Node
	if errs = yaml.Unmarshal(contents, &node); errs != nil {
		return nil, nil, fmt.Errorf("unable to parse yaml workflow file: %w", errs)
	}

	var ca compositeActionDef
	if errs = node.Decode(&ca); errs != nil {
		return nil, nil, fmt.Errorf("unable to parse yaml composite action file: %w", errs)
	}

	attachCompositeActionUsageComments(&node, ca.Runs.Steps)

	// we use a collection to help with deduplication before raising to higher level processing
	pkgs := pkg.NewCollection()

	for _, step := range ca.Runs.Steps {
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

	return pkgs.Sorted(), nil, errs
}

func attachCompositeActionUsageComments(node *yaml.Node, steps []stepDef) {
	root := node
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		root = root.Content[0]
	}
	if root.Kind != yaml.MappingNode {
		return
	}

	// find the "runs" key
	for i := 0; i < len(root.Content); i += 2 {
		key := root.Content[i]
		value := root.Content[i+1]
		if key.Value != "runs" || value.Kind != yaml.MappingNode {
			continue
		}
		// find the "steps" key within runs
		for j := 0; j < len(value.Content); j += 2 {
			stepsKey := value.Content[j]
			stepsValue := value.Content[j+1]
			if stepsKey.Value != "steps" || stepsValue.Kind != yaml.SequenceNode {
				continue
			}
			readSteps(stepsValue, steps)
		}
	}
}

func readSteps(stepsValue *yaml.Node, steps []stepDef) {
	// iterate over each step
	for stepIdx, stepNode := range stepsValue.Content {
		if stepNode.Kind != yaml.MappingNode {
			continue
		}
		// find the "uses" key within the step
		for k := 0; k < len(stepNode.Content); k += 2 {
			usesKey := stepNode.Content[k]
			usesValue := stepNode.Content[k+1]
			if usesKey.Value != "uses" || usesValue.Kind != yaml.ScalarNode {
				continue
			}
			comment := usesValue.LineComment
			if comment == "" {
				comment = usesValue.HeadComment
			}
			if comment == "" {
				comment = usesValue.FootComment
			}
			if comment == "" {
				continue
			}
			versionMatch := versionRegex.FindString(comment)
			if versionMatch != "" && stepIdx < len(steps) {
				steps[stepIdx].UsesComment = versionMatch
			}
		}
	}
}
