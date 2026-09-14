package options

import (
	"github.com/anchore/clio"
)

var _ clio.FieldDescriber = (*Convert)(nil)

// Convert holds the options specific to the convert command. These are deliberately configuration-only (config file
// or environment) rather than flags: they change how the command behaves for every invocation in a pipeline and are
// not expected to vary from one call to the next.
type Convert struct {
	PassthroughExactFormat bool `yaml:"passthrough-exact-format" json:"passthrough-exact-format" mapstructure:"passthrough-exact-format"`
}

func DefaultConvert() Convert {
	return Convert{
		PassthroughExactFormat: false,
	}
}

func (o *Convert) DescribeFields(descriptions clio.FieldDescriptionSet) {
	descriptions.Add(&o.PassthroughExactFormat, `when a syft-json input SBOM already exactly matches the requested output format and schema version, copy it to that output unchanged instead of decoding and re-encoding it.
Note: this only applies to syft-json input, and only when the document's schema version is identical to the schema version this version of syft produces. Any other input is always converted.
Note: output written this way is a byte-for-byte copy of the input, so format options (such as 'format.pretty' or 'format.json.legacy') are not applied to it.
Note: to keep memory use minimal on large documents, give the input as a file path (or a shell redirect) and write the output with '-o <format>=<path>'. Piped input, or output to STDOUT, requires the whole document to be held in memory.`)
}
