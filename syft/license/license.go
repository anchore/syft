// package license provides common methods for working with SPDX license data
package license

import "github.com/github/go-spdx/v2/spdxexp"

type Type string

const (
	Declared  Type = "declared"
	Concluded Type = "concluded"
)

type Evidence struct {
	Confidence int
	Offset     int
	Extent     int
}

func ParseExpression(expression string) (string, error) {
	node, err := spdxexp.Parse(expression)
	if err != nil {
		return "", err
	}
	if node == nil {
		return "", nil
	}
	return *node.ReconstructedLicenseString(), nil
}
