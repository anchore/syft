package alias

import (
	"encoding/xml"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/source"
)

// MavenProjectDirIdentifier augments name and version with what's found in a root pom.xml
func MavenProjectDirIdentifier(src source.Source) *source.Alias {
	type pomXML struct {
		Parent  *pomXML `xml:"parent"`
		Name    string  `xml:"name"`
		Version string  `xml:"version"`
	}

	// it's possible older layers would have a pom.xml that gets removed,
	// but we can probably skip identifying a directory as those
	r, err := src.FileResolver(source.SquashedScope)
	if err != nil {
		log.Debugf("error getting file resolver: %v", err)
		return nil
	}

	locs, err := r.FilesByPath("pom.xml")
	if err != nil {
		log.Debugf("error getting pom.xml: %v", err)
		return nil
	}

	// if we don't have exactly 1 pom.xml in the root directory, we can't guess which is the right one to use
	if len(locs) == 0 {
		// expected, not found
		return nil
	}
	if len(locs) > 1 {
		log.Debugf("multiple pom.xml files found: %v", locs)
		return nil
	}

	contents, err := r.FileContentsByLocation(locs[0])
	if err != nil {
		log.Tracef("error getting pom.xml contents: %v", err)
		return nil
	}
	defer internal.CloseAndLogError(contents, locs[0].RealPath)

	dec := xml.NewDecoder(contents)
	project := pomXML{}
	err = dec.Decode(&project)
	if err != nil {
		log.Tracef("error decoding pom.xml contents: %v", err)
		return nil
	}

	parent := pomXML{}
	if project.Parent != nil {
		parent = *project.Parent
	}

	return &source.Alias{
		Name:    project.Name,
		Version: nonEmpty(project.Version, parent.Version),
	}
}

// nonEmpty returns the first non-empty string provided
func nonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
