package java

import (
	"crypto"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/syft/artifact"
	syftFile "github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/common"
)

// integrity check
var _ common.ParserFn = parseJavaArchive

var archiveFormatGlobs = []string{
	"**/*.jar",
	"**/*.war",
	"**/*.ear",
	"**/*.par",
	"**/*.sar",
	"**/*.jpi",
	"**/*.hpi",
	"**/*.lpkg", // Zip-compressed package used to deploy applications
	// (aka plugins) to Liferay Portal server. Those files contains .JAR(s) and a .PROPERTIES file, the latter
	// has information about the application and installation requirements.
	// NOTE(jonasagx): If you would like to test it with lpkg file,
	// use: https://web.liferay.com/marketplace/-/mp/download/25019275/7403
	// LifeRay makes it pretty cumbersome to make a such plugins; their docs are
	// out of date, and they charge for their IDE. If you find an example
	// project that we can build in CI feel free to include it
}

// javaArchiveHashes are all the current hash algorithms used to calculate archive digests
var javaArchiveHashes = []crypto.Hash{
	crypto.SHA1,
}

type archiveParser struct {
	fileManifest file.ZipFileManifest
	virtualPath  string
	archivePath  string
	contentPath  string
	fileInfo     archiveFilename
	detectNested bool
}

// parseJavaArchive is a parser function for java archive contents, returning all Java libraries and nested archives.
func parseJavaArchive(virtualPath string, reader io.Reader) ([]*pkg.Package, []artifact.Relationship, error) {
	parser, cleanupFn, err := newJavaArchiveParser(virtualPath, reader, true)
	// note: even on error, we should always run cleanup functions
	defer cleanupFn()
	if err != nil {
		return nil, nil, err
	}
	return parser.parse()
}

// uniquePkgKey creates a unique string to identify the given package.
func uniquePkgKey(p *pkg.Package) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%s|%s", p.Name, p.Version)
}

// newJavaArchiveParser returns a new java archive parser object for the given archive. Can be configured to discover
// and parse nested archives or ignore them.
func newJavaArchiveParser(virtualPath string, reader io.Reader, detectNested bool) (*archiveParser, func(), error) {
	// fetch the last element of the virtual path
	virtualElements := strings.Split(virtualPath, ":")
	currentFilepath := virtualElements[len(virtualElements)-1]

	contentPath, archivePath, cleanupFn, err := saveArchiveToTmp(currentFilepath, reader)
	if err != nil {
		return nil, cleanupFn, fmt.Errorf("unable to process java archive: %w", err)
	}

	fileManifest, err := file.NewZipFileManifest(archivePath)
	if err != nil {
		return nil, cleanupFn, fmt.Errorf("unable to read files from java archive: %w", err)
	}

	return &archiveParser{
		fileManifest: fileManifest,
		virtualPath:  virtualPath,
		archivePath:  archivePath,
		contentPath:  contentPath,
		fileInfo:     newJavaArchiveFilename(currentFilepath),
		detectNested: detectNested,
	}, cleanupFn, nil
}

// parse the loaded archive and return all packages found.
func (j *archiveParser) parse() ([]*pkg.Package, []artifact.Relationship, error) {
	var pkgs []*pkg.Package
	var relationships []artifact.Relationship

	// find the parent package from the java manifest
	parentPkg, err := j.discoverMainPackage()
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate package from %s: %w", j.virtualPath, err)
	}

	// find aux packages from pom.properties/pom.xml and potentially modify the existing parentPkg
	// NOTE: we cannot generate sha1 digests from packages discovered via pom.properties/pom.xml
	auxPkgs, err := j.discoverPkgsFromAllMavenFiles(parentPkg)
	if err != nil {
		return nil, nil, err
	}
	pkgs = append(pkgs, auxPkgs...)

	if j.detectNested {
		// find nested java archive packages
		nestedPkgs, nestedRelationships, err := j.discoverPkgsFromNestedArchives(parentPkg)
		if err != nil {
			return nil, nil, err
		}
		pkgs = append(pkgs, nestedPkgs...)
		relationships = append(relationships, nestedRelationships...)
	}

	// lastly, add the parent package to the list (assuming the parent exists)
	if parentPkg != nil {
		pkgs = append([]*pkg.Package{parentPkg}, pkgs...)
	}

	// add pURLs to all packages found
	// note: since package information may change after initial creation when parsing multiple locations within the
	// jar, we wait until the conclusion of the parsing process before synthesizing pURLs.
	for _, p := range pkgs {
		addPURL(p)
	}

	return pkgs, relationships, nil
}

// discoverMainPackage parses the root Java manifest used as the parent package to all discovered nested packages.
func (j *archiveParser) discoverMainPackage() (*pkg.Package, error) {
	// search and parse java manifest files
	// TODO: do we want to prefer or check for pom files over manifest here?
	manifestMatches := j.fileManifest.GlobMatch(manifestGlob)
	if len(manifestMatches) > 1 {
		return nil, fmt.Errorf("found multiple manifests in the jar: %+v", manifestMatches)
	} else if len(manifestMatches) == 0 {
		// we did not find any manifests, but that may not be a problem (there may be other information to generate packages for)
		return nil, nil
	}

	// fetch the manifest file
	contents, err := file.ContentsFromZip(j.archivePath, manifestMatches...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract java manifests (%s): %w", j.virtualPath, err)
	}

	// parse the manifest file into a rich object
	manifestContents := contents[manifestMatches[0]]
	manifest, err := parseJavaManifest(j.archivePath, strings.NewReader(manifestContents))
	if err != nil {
		log.Warnf("failed to parse java manifest (%s): %+v", j.virtualPath, err)
		return nil, nil
	}

	archiveCloser, err := os.Open(j.archivePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open archive path (%s): %w", j.archivePath, err)
	}
	defer archiveCloser.Close()

	// grab and assign digest for the entire archive
	digests, err := syftFile.DigestsFromFile(archiveCloser, javaArchiveHashes)
	if err != nil {
		log.Warnf("failed to create digest for file=%q: %+v", j.archivePath, err)
	}

	return &pkg.Package{
		Name:         selectName(manifest, j.fileInfo),
		Version:      selectVersion(manifest, j.fileInfo),
		Language:     pkg.Java,
		Type:         j.fileInfo.pkgType(),
		MetadataType: pkg.JavaMetadataType,
		Metadata: pkg.JavaMetadata{
			VirtualPath:    j.virtualPath,
			Manifest:       manifest,
			ArchiveDigests: digests,
		},
	}, nil
}

// discoverPkgsFromAllMavenFiles parses Maven POM properties/xml for a given
// parent package, returning all listed Java packages found for each pom
// properties discovered and potentially updating the given parentPkg with new
// data.
func (j *archiveParser) discoverPkgsFromAllMavenFiles(parentPkg *pkg.Package) ([]*pkg.Package, error) {
	if parentPkg == nil {
		return nil, nil
	}

	var pkgs []*pkg.Package

	// pom.properties
	properties, err := pomPropertiesByParentPath(j.archivePath, j.virtualPath, j.fileManifest.GlobMatch(pomPropertiesGlob))
	if err != nil {
		return nil, err
	}

	// pom.xml
	projects, err := pomProjectByParentPath(j.archivePath, j.virtualPath, j.fileManifest.GlobMatch(pomXMLGlob))
	if err != nil {
		return nil, err
	}

	for parentPath, propertiesObj := range properties {
		var pomProject *pkg.PomProject
		if proj, exists := projects[parentPath]; exists {
			pomProject = &proj
		}

		pkgFromPom := newPackageFromMavenData(propertiesObj, pomProject, parentPkg, j.virtualPath)
		if pkgFromPom != nil {
			pkgs = append(pkgs, pkgFromPom)
		}
	}

	return pkgs, nil
}

func (j *archiveParser) discoverPkgsFromNestedArchives(parentPkg *pkg.Package) ([]*pkg.Package, []artifact.Relationship, error) {
	// we know that all java archives are zip formatted files, so we can use the shared zip helper
	return discoverPkgsFromZip(j.virtualPath, j.archivePath, j.contentPath, j.fileManifest, parentPkg)
}

// discoverPkgsFromZip finds Java archives within Java archives, returning all listed Java packages found and
// associating each discovered package to the given parent package.
func discoverPkgsFromZip(virtualPath, archivePath, contentPath string, fileManifest file.ZipFileManifest, parentPkg *pkg.Package) ([]*pkg.Package, []artifact.Relationship, error) {
	// search and parse pom.properties files & fetch the contents
	openers, err := file.ExtractFromZipToUniqueTempFile(archivePath, contentPath, fileManifest.GlobMatch(archiveFormatGlobs...)...)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to extract files from zip: %w", err)
	}

	return discoverPkgsFromOpeners(virtualPath, openers, parentPkg)
}

// discoverPkgsFromOpeners finds Java archives within the given files and associates them with the given parent package.
func discoverPkgsFromOpeners(virtualPath string, openers map[string]file.Opener, parentPkg *pkg.Package) ([]*pkg.Package, []artifact.Relationship, error) {
	var pkgs []*pkg.Package
	var relationships []artifact.Relationship

	for pathWithinArchive, archiveOpener := range openers {
		nestedPkgs, nestedRelationships, err := discoverPkgsFromOpener(virtualPath, pathWithinArchive, archiveOpener)
		if err != nil {
			log.Warnf("unable to discover java packages from opener (%s): %+v", virtualPath, err)
			continue
		}

		// attach the parent package to all discovered packages that are not already associated with a java archive
		for _, p := range nestedPkgs {
			if metadata, ok := p.Metadata.(pkg.JavaMetadata); ok {
				if metadata.Parent == nil {
					metadata.Parent = parentPkg
				}
				p.Metadata = metadata
			}
			pkgs = append(pkgs, p)
		}

		relationships = append(relationships, nestedRelationships...)
	}

	return pkgs, relationships, nil
}

// discoverPkgsFromOpener finds Java archives within the given file.
func discoverPkgsFromOpener(virtualPath, pathWithinArchive string, archiveOpener file.Opener) ([]*pkg.Package, []artifact.Relationship, error) {
	archiveReadCloser, err := archiveOpener.Open()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to open archived file from tempdir: %w", err)
	}
	defer func() {
		if closeErr := archiveReadCloser.Close(); closeErr != nil {
			log.Warnf("unable to close archived file from tempdir: %+v", closeErr)
		}
	}()

	nestedPath := fmt.Sprintf("%s:%s", virtualPath, pathWithinArchive)
	nestedPkgs, nestedRelationships, err := parseJavaArchive(nestedPath, archiveReadCloser)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to process nested java archive (%s): %w", pathWithinArchive, err)
	}

	return nestedPkgs, nestedRelationships, nil
}

func pomPropertiesByParentPath(archivePath, virtualPath string, extractPaths []string) (map[string]pkg.PomProperties, error) {
	contentsOfMavenPropertiesFiles, err := file.ContentsFromZip(archivePath, extractPaths...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract maven files: %w", err)
	}

	propertiesByParentPath := make(map[string]pkg.PomProperties)
	for filePath, fileContents := range contentsOfMavenPropertiesFiles {
		pomProperties, err := parsePomProperties(filePath, strings.NewReader(fileContents))
		if err != nil {
			log.Warnf("failed to parse pom.properties virtualPath=%q path=%q: %+v", virtualPath, filePath, err)
			continue
		}

		if pomProperties == nil {
			continue
		}

		if pomProperties.Version == "" || pomProperties.ArtifactID == "" {
			// TODO: if there is no parentPkg (no java manifest) one of these poms could be the parent. We should discover the right parent and attach the correct info accordingly to each discovered package
			continue
		}

		propertiesByParentPath[path.Dir(filePath)] = *pomProperties
	}

	return propertiesByParentPath, nil
}

func pomProjectByParentPath(archivePath, virtualPath string, extractPaths []string) (map[string]pkg.PomProject, error) {
	contentsOfMavenProjectFiles, err := file.ContentsFromZip(archivePath, extractPaths...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract maven files: %w", err)
	}

	projectByParentPath := make(map[string]pkg.PomProject)
	for filePath, fileContents := range contentsOfMavenProjectFiles {
		pomProject, err := parsePomXML(filePath, strings.NewReader(fileContents))
		if err != nil {
			log.Warnf("failed to parse pom.xml virtualPath=%q path=%q: %+v", virtualPath, filePath, err)
			continue
		}

		if pomProject == nil {
			continue
		}

		if pomProject.Version == "" || pomProject.ArtifactID == "" {
			// TODO: if there is no parentPkg (no java manifest) one of these poms could be the parent. We should discover the right parent and attach the correct info accordingly to each discovered package
			continue
		}

		projectByParentPath[path.Dir(filePath)] = *pomProject
	}
	return projectByParentPath, nil
}

// packagesFromPomProperties processes a single Maven POM properties for a given parent package, returning all listed Java packages found and
// associating each discovered package to the given parent package. Note the pom.xml is optional, the pom.properties is not.
func newPackageFromMavenData(pomProperties pkg.PomProperties, pomProject *pkg.PomProject, parentPkg *pkg.Package, virtualPath string) *pkg.Package {
	// keep the artifact name within the virtual path if this package does not match the parent package
	vPathSuffix := ""
	if !strings.HasPrefix(pomProperties.ArtifactID, parentPkg.Name) {
		vPathSuffix += ":" + pomProperties.ArtifactID
	}
	virtualPath += vPathSuffix

	// discovered props = new package
	p := pkg.Package{
		Name:         pomProperties.ArtifactID,
		Version:      pomProperties.Version,
		Language:     pkg.Java,
		Type:         pomProperties.PkgTypeIndicated(),
		MetadataType: pkg.JavaMetadataType,
		Metadata: pkg.JavaMetadata{
			VirtualPath:   virtualPath,
			PomProperties: &pomProperties,
			PomProject:    pomProject,
			Parent:        parentPkg,
		},
	}

	if packageIdentitiesMatch(p, parentPkg) {
		updateParentPackage(p, parentPkg)
		return nil
	}

	return &p
}

func packageIdentitiesMatch(p pkg.Package, parentPkg *pkg.Package) bool {
	// the name/version pair matches...
	if uniquePkgKey(&p) == uniquePkgKey(parentPkg) {
		return true
	}

	metadata := p.Metadata.(pkg.JavaMetadata)

	// the virtual path matches...
	if parentPkg.Metadata.(pkg.JavaMetadata).VirtualPath == metadata.VirtualPath {
		return true
	}

	// the pom artifactId is the parent name
	// note: you CANNOT use name-is-subset-of-artifact-id or vice versa --this is too generic. Shaded jars are a good
	// example of this: where the package name is "cloudbees-analytics-segment-driver" and a child is "analytics", but
	// they do not indicate the same package.
	if metadata.PomProperties.ArtifactID != "" && parentPkg.Name == metadata.PomProperties.ArtifactID {
		return true
	}

	return false
}

func updateParentPackage(p pkg.Package, parentPkg *pkg.Package) {
	// we've run across more information about our parent package, add this info to the parent package metadata
	// the pom properties is typically a better source of information for name and version than the manifest
	parentPkg.Name = p.Name
	parentPkg.Version = p.Version

	// we may have learned more about the type via data in the pom properties
	parentPkg.Type = p.Type

	metadata, ok := p.Metadata.(pkg.JavaMetadata)
	if !ok {
		return
	}
	pomPropertiesCopy := *metadata.PomProperties

	// keep the pom properties, but don't overwrite existing pom properties
	parentMetadata, ok := parentPkg.Metadata.(pkg.JavaMetadata)
	if ok && parentMetadata.PomProperties == nil {
		parentMetadata.PomProperties = &pomPropertiesCopy
		parentPkg.Metadata = parentMetadata
	}
}

func addPURL(p *pkg.Package) {
	purl := packageURL(*p)
	if purl == "" {
		return
	}

	metadata, ok := p.Metadata.(pkg.JavaMetadata)
	if !ok {
		return
	}
	metadata.PURL = purl
	p.Metadata = metadata
}
