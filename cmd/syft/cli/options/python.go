package options

type python struct {
	GuessUnpinnedRequirements bool `json:"guess-unpinned-requirements" yaml:"guess-unpinned-requirements" mapstructure:"guess-unpinned-requirements"`
}
