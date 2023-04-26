// package license provides common methods for working with SPDX license data
package license

import (
	"fmt"

	"github.com/github/go-spdx/v2/spdxexp"

	"github.com/anchore/syft/internal/spdxlicense"
)

type Type string

const (
	Declared  Type = "declared"
	Concluded Type = "concluded"
)

func ParseExpression(expression string) (string, error) {
	licenseID, exists := spdxlicense.ID(expression)
	if exists {
		return licenseID, nil
	}

	// If it doesn't exist initially in the SPDX list it might be a more complex expression
	// ignored variable is any invalid expressions
	// TODO: contribute to spdxexp to expose deprecated license IDs
	valid, _ := spdxexp.ValidateLicenses([]string{expression})
	if !valid {
		return "", fmt.Errorf("failed to validate spdx expression: %s", expression)
	}

	return expression, nil
}
