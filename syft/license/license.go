// package license provides common methods for working with SPDX license data
package license

import (
	"fmt"

	"github.com/github/go-spdx/v2/spdxexp"
)

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
	// returns true if all licenses are valid
	// ignored variable is any invalid expressions
	valid, _ := spdxexp.ValidateLicenses([]string{expression})
	if !valid {
		return "", fmt.Errorf("failed to validate spdx expression: %s", expression)
	}

	return expression, nil
}
