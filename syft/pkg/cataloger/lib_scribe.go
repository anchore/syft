package cataloger

import (
	"fmt"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/pkg"
)

func FilterCatalogers(cfg Config, groupCatalogers []pkg.Cataloger) []pkg.Cataloger {
	return filterCatalogers(groupCatalogers, cfg.Catalogers)
}

func SelectGroup(cfg Config) ([]pkg.Cataloger, error) {
	switch cfg.CatalogerGroup {
	case IndexGroup:
		log.Info("cataloging index group")
		return DirectoryCatalogers(cfg), nil
	case InstallationGroup:
		log.Info("cataloging installation group")
		return ImageCatalogers(cfg), nil
	case AllGroup:
		log.Info("cataloging all group")
		return AllCatalogers(cfg), nil
	default:
		return nil, fmt.Errorf("unknown cataloger group, Group: %s", cfg.CatalogerGroup)
	}
}

type Group string

const (
	IndexGroup        Group = "index"
	InstallationGroup Group = "install"
	AllGroup          Group = "all"
)

var AllGroups = []Group{
	IndexGroup,
	InstallationGroup,
	AllGroup,
}
