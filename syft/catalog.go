package syft

import (
	"fmt"
	"github.com/anchore/syft/internal/bus"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/event"
	"github.com/anchore/syft/syft/event/monitor"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
	"github.com/hashicorp/go-multierror"
	"github.com/wagoodman/go-partybus"
	"github.com/wagoodman/go-progress"
)

type monitorableCollection struct {
	pkg.Collection
	monitor *progress.Manual
}

func (m *monitorableCollection) Add(p pkg.Package) {
	m.monitor.N++
	m.Collection.Add(p)
}

func Catalog(src *source.Source, options ...CatalogingOption) (*sbom.SBOM, error) {
	var config = DefaultCatalogingConfig()
	for _, optFn := range options {
		if err := optFn(src, &config); err != nil {
			return nil, fmt.Errorf("unable to apply cataloging option: %w", err)
		}
	}

	if config.availableTasks == nil {
		var err error
		config.availableTasks, err = newTaskCollection()
		if err != nil {
			return nil, err
		}
	}

	if len(config.EnabledCatalogers) == 0 {
		return nil, fmt.Errorf("no cataloging tasks configured to run")
	}

	catalogingTasks, err := config.availableTasks.tasks(config, config.EnabledCatalogers...)
	if err != nil {
		return nil, err
	}

	if len(catalogingTasks) == 0 {
		return nil, fmt.Errorf("no cataloging tasks found to run")
	}

	// special case: we need to identify the linux distro for downstream processing
	identifyLinuxDistroTask, err := newIdentifyDistroTask(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create linux distro identification task: %+v", err)
	}

	synthesizePackageRelationshipsTask, err := newSynthesizePackageRelationshipsTasks(config)
	if err != nil {
		return nil, fmt.Errorf("unable to create task to synthesize package relationships: %+v", err)
	}

	taskGroups := [][]task{
		{
			identifyLinuxDistroTask,
		},
		catalogingTasks,
		{
			synthesizePackageRelationshipsTask,
		},
	}

	files, pkgs := newCatalogerMonitor()
	defer func() {
		files.SetCompleted() // TODO: files monitor is unused... should we remove?
		pkgs.SetCompleted()
	}()

	s := sbom.SBOM{
		Source: src.Metadata,
		Descriptor: sbom.Descriptor{
			Name:          config.ToolName,
			Version:       config.ToolVersion,
			Configuration: config.ToolConfiguration,
		},
		Artifacts: sbom.Artifacts{
			Packages: &monitorableCollection{
				Collection: pkg.NewCollection(),
				monitor:    pkgs,
			},
		},
	}

	for _, tasks := range taskGroups {
		if err := runTasks(&s, src, config.ProcessTasksInSerial, tasks...); err != nil {
			return &s, err
		}
	}

	return &s, nil
}

// newCatalogerMonitor creates a new CatalogingMonitor object and publishes the object on the bus as a CatalogingStarted event.
func newCatalogerMonitor() (*progress.Manual, *progress.Manual) {
	filesProcessed := progress.Manual{}
	packagesDiscovered := progress.Manual{}

	bus.Publish(partybus.Event{
		Type: event.CatalogingStarted,
		Value: monitor.CatalogingMonitor{
			FilesProcessed:     progress.Monitorable(&filesProcessed),
			PackagesDiscovered: progress.Monitorable(&packagesDiscovered),
		},
	})
	return &filesProcessed, &packagesDiscovered
}

func runTasks(s *sbom.SBOM, src *source.Source, serial bool, tasks ...task) error {
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

	relationships, err := t.Run(a, src)
	if err != nil {
		errs <- err
		return
	}

	for _, relationship := range relationships {
		r <- relationship
	}
}
