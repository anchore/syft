package testutil

import (
	"math/rand"
	"time"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/sbom"
)

//nolint:gosec
func AddSampleFileRelationships(s *sbom.SBOM) {
	catalog := s.Artifacts.Packages.Sorted()
	s.Artifacts.FileMetadata = map[file.Coordinates]file.Metadata{}

	files := []string{"/f1", "/f2", "/d1/f3", "/d2/f4", "/z1/f5", "/a1/f6"}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	rnd.Shuffle(len(files), func(i, j int) { files[i], files[j] = files[j], files[i] })

	for _, f := range files {
		meta := file.Metadata{}
		coords := file.Coordinates{RealPath: f}
		s.Artifacts.FileMetadata[coords] = meta

		s.Relationships = append(s.Relationships, artifact.Relationship{
			From: catalog[0],
			To:   coords,
			Type: artifact.ContainsRelationship,
		})
	}
}
