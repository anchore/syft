package options

import "github.com/anchore/clio"

type pythonConfig struct {
	GuessUnpinnedRequirements bool `json:"guess-unpinned-requirements" yaml:"guess-unpinned-requirements" mapstructure:"guess-unpinned-requirements"`
}

var _ interface {
	clio.FieldDescriber
} = (*pythonConfig)(nil)

func (o *pythonConfig) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.GuessUnpinnedRequirements, `when running across entries in requirements.txt that do not specify a specific version 
(e.g. "sqlalchemy >= 1.0.0, <= 2.0.0, != 3.0.0, <= 3.0.0"), attempt to guess what the version could
be based on the version requirements specified (e.g. "1.0.0"). When enabled the lowest expressible version 
when given an arbitrary constraint will be used (even if that version may not be available/published).`)
}
