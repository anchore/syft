package unknown

import (
	"regexp"

	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/file"
)

var pathErrorRegex = regexp.MustCompile(`.*path="([^"]+)".*`)

// ProcessPathErrors replaces "path" errors returned from the file.Resolver into unknowns,
// and warn logs non-unknown errors, returning only the unknown errors
func ProcessPathErrors(err error) error {
	if err == nil {
		return nil
	}
	errText := err.Error()
	if pathErrorRegex.MatchString(errText) {
		foundPath := pathErrorRegex.ReplaceAllString(err.Error(), "$1")
		if foundPath != "" {
			return New(file.NewLocation(foundPath), err)
		}
	}
	unknowns, remainingErrors := ExtractCoordinateErrors(err)
	log.Debug(remainingErrors)

	var out []error
	for _, u := range unknowns {
		out = append(out, &u)
	}
	return Join(out...)
}
