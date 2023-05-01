package syftjson

import (
	"os"
	"strconv"
	"strings"

	"github.com/google/go-cmp/cmp"

	stereoscopeFile "github.com/anchore/stereoscope/pkg/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/formats/syftjson/model"
	"github.com/anchore/syft/syft/linux"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

func toSyftModel(doc model.Document) (*sbom.SBOM, error) {
	idAliases := make(map[string]string)

	catalog := toSyftCatalog(doc.Artifacts, idAliases)

	fileArtifacts := toSyftFiles(doc.Files)

	return &sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages:          catalog,
			FileMetadata:      fileArtifacts.FileMetadata,
			FileDigests:       fileArtifacts.FileDigests,
			LinuxDistribution: toSyftLinuxRelease(doc.Distro),
		},
		Source:        *toSyftSourceData(doc.Source),
		Descriptor:    toSyftDescriptor(doc.Descriptor),
		Relationships: toSyftRelationships(&doc, catalog, doc.ArtifactRelationships, idAliases),
	}, nil
}

func toSyftFiles(files []model.File) sbom.Artifacts {
	ret := sbom.Artifacts{
		FileMetadata: make(map[source.Coordinates]source.FileMetadata),
		FileDigests:  make(map[source.Coordinates][]file.Digest),
	}

	for _, f := range files {
		coord := f.Location
		if f.Metadata != nil {
			mode, err := strconv.ParseInt(strconv.Itoa(f.Metadata.Mode), 8, 64)
			if err != nil {
				log.Warnf("invalid mode found in file catalog @ location=%+v mode=%q: %+v", coord, f.Metadata.Mode, err)
				mode = 0
			}

			fm := os.FileMode(mode)

			ret.FileMetadata[coord] = source.FileMetadata{
				Path:            coord.RealPath,
				LinkDestination: f.Metadata.LinkDestination,
				Size:            f.Metadata.Size,
				UserID:          f.Metadata.UserID,
				GroupID:         f.Metadata.GroupID,
				Type:            toSyftFileType(f.Metadata.Type),
				IsDir:           fm.IsDir(),
				Mode:            fm,
				MIMEType:        f.Metadata.MIMEType,
			}
		}

		for _, d := range f.Digests {
			ret.FileDigests[coord] = append(ret.FileDigests[coord], file.Digest{
				Algorithm: d.Algorithm,
				Value:     d.Value,
			})
		}
	}

	return ret
}

func toSyftFileType(ty string) stereoscopeFile.Type {
	switch ty {
	case "SymbolicLink":
		return stereoscopeFile.TypeSymLink
	case "HardLink":
		return stereoscopeFile.TypeHardLink
	case "Directory":
		return stereoscopeFile.TypeDirectory
	case "Socket":
		return stereoscopeFile.TypeSocket
	case "BlockDevice":
		return stereoscopeFile.TypeBlockDevice
	case "CharacterDevice":
		return stereoscopeFile.TypeCharacterDevice
	case "FIFONode":
		return stereoscopeFile.TypeFIFO
	case "RegularFile":
		return stereoscopeFile.TypeRegular
	case "IrregularFile":
		return stereoscopeFile.TypeIrregular
	default:
		return stereoscopeFile.TypeIrregular
	}
}

func toSyftLinuxRelease(d model.LinuxRelease) *linux.Release {
	if cmp.Equal(d, model.LinuxRelease{}) {
		return nil
	}
	return &linux.Release{
		PrettyName:       d.PrettyName,
		Name:             d.Name,
		ID:               d.ID,
		IDLike:           d.IDLike,
		Version:          d.Version,
		VersionID:        d.VersionID,
		VersionCodename:  d.VersionCodename,
		BuildID:          d.BuildID,
		ImageID:          d.ImageID,
		ImageVersion:     d.ImageVersion,
		Variant:          d.Variant,
		VariantID:        d.VariantID,
		HomeURL:          d.HomeURL,
		SupportURL:       d.SupportURL,
		BugReportURL:     d.BugReportURL,
		PrivacyPolicyURL: d.PrivacyPolicyURL,
		CPEName:          d.CPEName,
		SupportEnd:       d.SupportEnd,
	}
}

func toSyftRelationships(doc *model.Document, catalog *pkg.Collection, relationships []model.Relationship, idAliases map[string]string) []artifact.Relationship {
	idMap := make(map[string]interface{})

	for _, p := range catalog.Sorted() {
		idMap[string(p.ID())] = p
		locations := p.Locations.ToSlice()
		for _, l := range locations {
			idMap[string(l.Coordinates.ID())] = l.Coordinates
		}
	}

	// set source metadata in identifier map
	idMap[doc.Source.ID] = toSyftSource(doc.Source)

	for _, f := range doc.Files {
		idMap[f.ID] = f.Location
	}

	var out []artifact.Relationship
	for _, r := range relationships {
		syftRelationship := toSyftRelationship(idMap, r, idAliases)
		if syftRelationship != nil {
			out = append(out, *syftRelationship)
		}
	}
	return out
}

func toSyftSource(s model.Source) *source.Source {
	newSrc := &source.Source{
		Metadata: *toSyftSourceData(s),
	}
	newSrc.SetID()
	return newSrc
}

func toSyftRelationship(idMap map[string]interface{}, relationship model.Relationship, idAliases map[string]string) *artifact.Relationship {
	id := func(id string) string {
		aliased, ok := idAliases[id]
		if ok {
			return aliased
		}
		return id
	}

	from, ok := idMap[id(relationship.Parent)].(artifact.Identifiable)
	if !ok {
		log.Warnf("relationship mapping from key %s is not a valid artifact.Identifiable type: %+v", relationship.Parent, idMap[relationship.Parent])
		return nil
	}

	to, ok := idMap[id(relationship.Child)].(artifact.Identifiable)
	if !ok {
		log.Warnf("relationship mapping to key %s is not a valid artifact.Identifiable type: %+v", relationship.Child, idMap[relationship.Child])
		return nil
	}

	typ := artifact.RelationshipType(relationship.Type)

	switch typ {
	case artifact.OwnershipByFileOverlapRelationship, artifact.ContainsRelationship, artifact.DependencyOfRelationship, artifact.EvidentByRelationship:
	default:
		if !strings.Contains(string(typ), "dependency-of") {
			log.Warnf("unknown relationship type: %s", typ)
			return nil
		}
		// lets try to stay as compatible as possible with similar relationship types without dropping the relationship
		log.Warnf("assuming %q for relationship type %q", artifact.DependencyOfRelationship, typ)
		typ = artifact.DependencyOfRelationship
	}
	return &artifact.Relationship{
		From: from,
		To:   to,
		Type: typ,
		Data: relationship.Metadata,
	}
}

func toSyftDescriptor(d model.Descriptor) sbom.Descriptor {
	return sbom.Descriptor{
		Name:          d.Name,
		Version:       d.Version,
		Configuration: d.Configuration,
	}
}

func toSyftSourceData(s model.Source) *source.Metadata {
	switch s.Type {
	case "directory":
		path, ok := s.Target.(string)
		if !ok {
			log.Warnf("unable to parse source target as string: %+v", s.Target)
			return nil
		}
		return &source.Metadata{
			ID:     s.ID,
			Scheme: source.DirectoryScheme,
			Path:   path,
		}
	case "file":
		path, ok := s.Target.(string)
		if !ok {
			log.Warnf("unable to parse source target as string: %+v", s.Target)
			return nil
		}
		return &source.Metadata{
			ID:     s.ID,
			Scheme: source.FileScheme,
			Path:   path,
		}
	case "image":
		metadata, ok := s.Target.(source.ImageMetadata)
		if !ok {
			log.Warnf("unable to parse source target as image metadata: %+v", s.Target)
			return nil
		}
		return &source.Metadata{
			ID:            s.ID,
			Scheme:        source.ImageScheme,
			ImageMetadata: metadata,
		}
	}
	return nil
}

func toSyftCatalog(pkgs []model.Package, idAliases map[string]string) *pkg.Collection {
	catalog := pkg.NewCollection()
	for _, p := range pkgs {
		catalog.Add(toSyftPackage(p, idAliases))
	}
	return catalog
}

func toSyftPackage(p model.Package, idAliases map[string]string) pkg.Package {
	var cpes []cpe.CPE
	for _, c := range p.CPEs {
		value, err := cpe.New(c)
		if err != nil {
			log.Warnf("excluding invalid CPE %q: %v", c, err)
			continue
		}

		cpes = append(cpes, value)
	}

	out := pkg.Package{
		Name:         p.Name,
		Version:      p.Version,
		FoundBy:      p.FoundBy,
		Locations:    source.NewLocationSet(p.Locations...),
		Licenses:     p.Licenses,
		Language:     p.Language,
		Type:         p.Type,
		CPEs:         cpes,
		PURL:         p.PURL,
		MetadataType: p.MetadataType,
		Metadata:     p.Metadata,
	}

	// we don't know if this package ID is truly unique, however, we need to trust the user input in case there are
	// external references to it. That is, we can't derive our own ID (using pkg.SetID()) since consumers won't
	// be able to historically interact with data that references the IDs from the original SBOM document being decoded now.
	out.OverrideID(artifact.ID(p.ID))

	// this alias mapping is currently defunct, but could be useful in the future.
	id := string(out.ID())
	if id != p.ID {
		idAliases[p.ID] = id
	}

	return out
}
