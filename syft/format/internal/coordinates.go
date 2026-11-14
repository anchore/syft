package internal

import (
	"strings"

	"github.com/anchore/syft/internal/archive"
	"github.com/anchore/syft/syft/file"
)

// NestedCoordinates returns the coordinates of the entry named name directly within the archive at container,
// reporting false for a name a scan would refuse as an entry name, for nesting deeper than a scan goes, or for
// a chain longer than archive.MaxPathBytes. A decoded document can then only build chains bounded in depth and
// length.
func NestedCoordinates(container file.Coordinates, name string) (file.Coordinates, bool) {
	if nestingDepth(container) >= archive.MaxDepth {
		return file.Coordinates{}, false
	}
	entry, err := archive.EntryName(name)
	if err != nil || entry == "" {
		return file.Coordinates{}, false
	}
	chain := container.FullNestedPath()
	if len(chain)+len(file.ArchivePathSeparator)+len(entry) > archive.MaxPathBytes {
		return file.Coordinates{}, false
	}
	return file.Coordinates{
		RealPath:     container.RealPath,
		FileSystemID: container.FileSystemID,
		FullPath:     chain + file.ArchivePathSeparator + entry,
	}, true
}

// NormalizeCoordinates returns decoded coordinates in the form a resolver builds them, reporting false for a
// FullPath that is not a chain NestedCoordinates could have built within RealPath. Such a file is dropped rather
// than collapsed onto RealPath, where it would merge into the outer archive's own entry. A FullPath merely equal
// to RealPath is cleared.
func NormalizeCoordinates(c file.Coordinates) (file.Coordinates, bool) {
	if c.FullPath == "" || c.FullPath == c.RealPath {
		c.FullPath = ""
		return c, true
	}
	rest, ok := strings.CutPrefix(c.FullPath, c.RealPath+file.ArchivePathSeparator)
	// counted before splitting, so a hostile chain costs nothing to refuse
	if !ok || len(c.FullPath) > archive.MaxPathBytes || strings.Count(rest, file.ArchivePathSeparator) >= archive.MaxDepth {
		return file.Coordinates{}, false
	}
	for _, entry := range strings.Split(rest, file.ArchivePathSeparator) {
		if cleaned, err := archive.EntryName(entry); err != nil || cleaned == "" || cleaned != entry {
			return file.Coordinates{}, false
		}
	}
	return c, true
}

// NormalizeLocations applies NormalizeCoordinates to each location, dropping those it refuses.
func NormalizeLocations(locations []file.Location) []file.Location {
	var out []file.Location
	for _, l := range locations {
		if c, ok := NormalizeCoordinates(l.Coordinates); ok {
			l.Coordinates = c
			out = append(out, l)
		}
	}
	return out
}

// nestingDepth is how many archives deep the file at c is.
func nestingDepth(c file.Coordinates) int {
	rest, ok := strings.CutPrefix(c.FullPath, c.RealPath)
	if !ok {
		return 0
	}
	return strings.Count(rest, file.ArchivePathSeparator)
}
