// this file retrieves the canonical list of cataloger names and their selectors from syft's task factories.
package internal

import (
	"fmt"
	"sort"

	"github.com/anchore/syft/internal/capabilities"
	"github.com/anchore/syft/internal/task"
)

// AllPackageCatalogerInfo gets all package cataloger info (names and selectors) from task factories
func AllPackageCatalogerInfo() ([]capabilities.CatalogerInfo, error) {
	pkgTaskFactories := task.DefaultPackageTaskFactories()
	allPkgTasks, err := pkgTaskFactories.Tasks(task.DefaultCatalogingFactoryConfig())
	if err != nil {
		return nil, fmt.Errorf("unable to create pkg cataloger tasks: %w", err)
	}

	infos := capabilities.ExtractCatalogerInfo(allPkgTasks)

	// sort by name for consistency
	sort.Slice(infos, func(i, j int) bool {
		return infos[i].Name < infos[j].Name
	})

	return infos, nil
}
