package java

import (
	"fmt"

	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
)

// MavenID is an exported wrapper around the internal maven.ID type, allowing
// packages outside the java cataloger to work with Maven coordinates.
type MavenID struct {
	GroupID    string
	ArtifactID string
	Version    string
}

func NewMavenID(groupID, artifactID, version string) MavenID {
	return MavenID{
		GroupID:    groupID,
		ArtifactID: artifactID,
		Version:    version,
	}
}

func (m MavenID) String() string {
	return fmt.Sprintf("%s:%s:%s", m.GroupID, m.ArtifactID, m.Version)
}

func (m MavenID) Valid() bool {
	return m.GroupID != "" && m.ArtifactID != "" && m.Version != ""
}

func (m MavenID) toInternalID() maven.ID {
	return maven.NewID(m.GroupID, m.ArtifactID, m.Version)
}
