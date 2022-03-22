package syft

import (
	"fmt"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/hashicorp/go-multierror"
)

func Catalog(src *source.Source, options ...CatalogingOption) (*sbom.SBOM, error) {
	var config = DefaultCatalogingConfig()
	for _, optFn := range options {
		if err := optFn(src, &config); err != nil {
			return nil, fmt.Errorf("unable to apply cataloging option: %w", err)
		}
	}

	var tasks []task

	generators := []taskGenerator{
		generatePackagesCatalogingTask,
		generateFileMetadataCatalogingTask,
		generateFileDigestsCatalogingTask,
		generateSecretsCatalogingTask,
		generateFileClassifierTask,
		generateContentsCatalogingTask,
	}

	for _, generator := range generators {
		t, err := generator(config)
		if err != nil {
			return nil, fmt.Errorf("unable to create cataloging task: %w", err)
		}

		if t != nil {
			tasks = append(tasks, t)
		}
	}

	s := sbom.SBOM{
		Source: src.Metadata,
		Descriptor: sbom.Descriptor{
			Name:          config.ToolName,
			Version:       config.ToolVersion,
			Configuration: config.ToolConfiguration,
		},
	}

	return &s, runTasks(&s, src, tasks, config.ProcessTasksInSerial)
}

func runTasks(s *sbom.SBOM, src *source.Source, tasks []task, serial bool) error {
	var relationships []<-chan artifact.Relationship
	var errs = make(chan error)
	for _, t := range tasks {
		r := make(chan artifact.Relationship)
		relationships = append(relationships, r)
		if serial {
			runTask(t, &s.Artifacts, src, r, errs)
		} else {
			go runTask(t, &s.Artifacts, src, r, errs)
		}
	}

	s.Relationships = append(s.Relationships, mergeRelationships(relationships...)...)
	close(errs)
	return mergeErrors(errs)
}

func mergeRelationships(cs ...<-chan artifact.Relationship) (relationships []artifact.Relationship) {
	for _, c := range cs {
		for n := range c {
			relationships = append(relationships, n)
		}
	}

	return relationships
}

func mergeErrors(errs <-chan error) (allErrs error) {
	for err := range errs {
		if err != nil {
			allErrs = multierror.Append(allErrs, err)
		}
	}

	return allErrs
}

func runTask(t task, a *sbom.Artifacts, src *source.Source, r chan<- artifact.Relationship, errs chan<- error) {
	defer close(r)

	relationships, err := t(a, src)
	if err != nil {
		errs <- err
		return
	}

	for _, relationship := range relationships {
		r <- relationship
	}
}
