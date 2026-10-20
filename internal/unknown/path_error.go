package unknown

import (
	"regexp"
	"strings"

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
			return New(file.NewLocationFromCoordinates(pathCoordinates(foundPath)), err)
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

// pathCoordinates names the file at a path from a resolver error, which for a file within an archive is
// a full path: the real path is what precedes the first archive separator.
func pathCoordinates(p string) file.Coordinates {
	realPath, _, nested := strings.Cut(p, file.ArchivePathSeparator)
	if !nested {
		return file.NewCoordinates(p, "")
	}
	return file.Coordinates{RealPath: realPath, FullPath: p}
}
