package options

import (
	"fmt"

	"github.com/anchore/clio"
	"github.com/anchore/fangs"
)

type CatalogerSelection struct {
	// high-level cataloger configuration
	Catalogers        []string `yaml:"-" json:"catalogers" mapstructure:"catalogers"` // deprecated and not shown in yaml output
	DefaultCatalogers []string `yaml:"default-catalogers" json:"default-catalogers" mapstructure:"default-catalogers"`
	SelectCatalogers  []string `yaml:"select-catalogers" json:"select-catalogers" mapstructure:"select-catalogers"`
}

var _ interface {
	clio.FlagAdder
	clio.PostLoader
} = (*CatalogerSelection)(nil)

func (cfg *CatalogerSelection) AddFlags(flags clio.FlagSet) {
	flags.StringArrayVarP(&cfg.Catalogers, "catalogers", "",
		"enable one or more package catalogers")

	if pfp, ok := flags.(fangs.PFlagSetProvider); ok {
		if err := pfp.PFlagSet().MarkDeprecated("catalogers", "use: override-default-catalogers and select-catalogers"); err != nil {
			panic(err)
		}
	} else {
		panic("unable to mark flags as deprecated")
	}

	flags.StringArrayVarP(&cfg.DefaultCatalogers, "override-default-catalogers", "",
		"set the base set of catalogers to use (defaults to 'image' or 'directory' depending on the scan source)")

	flags.StringArrayVarP(&cfg.SelectCatalogers, "select-catalogers", "",
		"add, remove, and filter the catalogers to be used")
}

func (cfg *CatalogerSelection) PostLoad() error {
	usingLegacyCatalogers := len(cfg.Catalogers) > 0
	usingNewCatalogers := len(cfg.DefaultCatalogers) > 0 || len(cfg.SelectCatalogers) > 0

	if usingLegacyCatalogers && usingNewCatalogers {
		return fmt.Errorf("cannot use both 'catalogers' and 'select-catalogers'/'default-catalogers' flags %q | %q %q", cfg.Catalogers, cfg.SelectCatalogers, cfg.DefaultCatalogers)
	}

	cfg.Catalogers = FlattenAndSort(cfg.Catalogers)
	cfg.DefaultCatalogers = FlattenAndSort(cfg.DefaultCatalogers)
	cfg.SelectCatalogers = FlattenAndSort(cfg.SelectCatalogers)

	// for backwards compatibility
	cfg.DefaultCatalogers = append(cfg.DefaultCatalogers, cfg.Catalogers...)

	return nil
}
