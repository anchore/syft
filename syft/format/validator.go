package format

import "io"

// Validator reads the SBOM from the given reader and assesses whether the document conforms to the specific SBOM format.
// The validator should positively confirm if the SBOM is not only the format but also has the minimal set of values
// that the format requires. For example, all syftjson formatted documents have a schema section which should have
// "anchore/syft" within the version --if this isn't found then the validator should raise an error. These active
// assertions protect against "simple" format decoding validations that may lead to false positives (e.g. I decoded
// json successfully therefore this must be the target format, however, all values are their default zero-value and
// really represent a different format that also uses json)
type Validator interface {
	Validate(reader io.Reader) error
}
