package java

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	"golang.org/x/exp/maps"

	"github.com/anchore/syft/internal"
	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/internal/licenses"
	"github.com/anchore/syft/internal/log"
	"github.com/anchore/syft/internal/unknown"
	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/pkg/cataloger/java/internal/maven"
)

var archiveFormatGlobs = []string{
	"**/*.jar",
	"**/*.war",
	"**/*.ear",
	"**/*.par",
	"**/*.sar",
	"**/*.nar",
	"**/*.jpi",
	"**/*.hpi",
	"**/*.kar",
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
	fileManifest   intFile.ZipFileManifest
	location       file.Location
	archivePath    string
	contentPath    string
	fileInfo       archiveFilename
	detectNested   bool
	cfg            ArchiveCatalogerConfig
	maven          *maven.Resolver
	licenseScanner licenses.Scanner
}

type genericArchiveParserAdapter struct {
	cfg ArchiveCatalogerConfig
}

func newGenericArchiveParserAdapter(cfg ArchiveCatalogerConfig) genericArchiveParserAdapter {
	return genericArchiveParserAdapter{cfg: cfg}
}

// parseJavaArchive is a parser function for java archive contents, returning all Java libraries and nested archives
func (gap genericArchiveParserAdapter) parseJavaArchive(ctx context.Context, _ file.Resolver, _ *generic.Environment, reader file.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	return gap.processJavaArchive(ctx, reader, nil)
}

// processJavaArchive processes an archive for java contents, returning all Java libraries and nested archives
func (gap genericArchiveParserAdapter) processJavaArchive(ctx context.Context, reader file.LocationReadCloser, parentPkg *pkg.Package) ([]pkg.Package, []artifact.Relationship, error) {
	parser, cleanupFn, err := newJavaArchiveParser(ctx, reader, true, gap.cfg)
	// note: even on error, we should always run cleanup functions
	defer cleanupFn()
	if err != nil {
		return nil, nil, err
	}
	return parser.parse(ctx, parentPkg)
}

// uniquePkgKey creates a unique string to identify the given package.
func uniquePkgKey(groupID string, p *pkg.Package) string {
	if p == nil {
		return ""
	}
	return fmt.Sprintf("%s|%s|%s", groupID, p.Name, p.Version)
}

// newJavaArchiveParser returns a new java archive parser object for the given archive. Can be configured to discover
// and parse nested archives or ignore them.
func newJavaArchiveParser(ctx context.Context, reader file.LocationReadCloser, detectNested bool, cfg ArchiveCatalogerConfig) (*archiveParser, func(), error) {
	licenseScanner, err := licenses.ContextLicenseScanner(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("could not build license scanner for java archive parser: %w", err)
	}

	// fetch the last element of the virtual path
	virtualElements := strings.Split(reader.Path(), ":")
	currentFilepath := virtualElements[len(virtualElements)-1]

	contentPath, archivePath, cleanupFn, err := saveArchiveToTmp(currentFilepath, reader)
	if err != nil {
		return nil, cleanupFn, fmt.Errorf("unable to process java archive: %w", err)
	}

	fileManifest, err := intFile.NewZipFileManifest(ctx, archivePath)
	if err != nil {
		return nil, cleanupFn, fmt.Errorf("unable to read files from java archive: %w", err)
	}

	return &archiveParser{
		fileManifest:   fileManifest,
		location:       reader.Location,
		archivePath:    archivePath,
		contentPath:    contentPath,
		fileInfo:       newJavaArchiveFilename(currentFilepath),
		detectNested:   detectNested,
		cfg:            cfg,
		maven:          maven.NewResolver(nil, cfg.mavenConfig()),
		licenseScanner: licenseScanner,
	}, cleanupFn, nil
}

// parse the loaded archive and return all packages found.
func (j *archiveParser) parse(ctx context.Context, parentPkg *pkg.Package) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	// find the parent package from the java manifest
	mainPkg, err := j.discoverMainPackage(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("could not generate package from %s: %w", j.location, err)
	}

	// find aux packages from pom.properties/pom.xml and potentially modify the existing parentPkg
	// NOTE: we cannot generate sha1 digests from packages discovered via pom.properties/pom.xml
	// IMPORTANT!: discoverPkgsFromAllMavenFiles may change mainPkg information, so needs to be called before SetID and before copying for relationships, etc.
	auxPkgs, err := j.discoverPkgsFromAllMavenFiles(ctx, mainPkg)
	if err != nil {
		return nil, nil, err
	}

	if mainPkg != nil {
		finalizePackage(mainPkg)
		pkgs = append(pkgs, *mainPkg)

		if parentPkg != nil {
			relationships = append(relationships, artifact.Relationship{
				From: *mainPkg,
				To:   *parentPkg,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}

	for i := range auxPkgs {
		auxPkg := &auxPkgs[i]

		finalizePackage(auxPkg)
		pkgs = append(pkgs, *auxPkg)

		if mainPkg != nil {
			relationships = append(relationships, artifact.Relationship{
				From: *auxPkg,
				To:   *mainPkg,
				Type: artifact.DependencyOfRelationship,
			})
		}
	}

	var errs error
	if j.detectNested {
		// find nested java archive packages
		nestedPkgs, nestedRelationships, err := j.discoverPkgsFromNestedArchives(ctx, mainPkg)
		if err != nil {
			errs = unknown.Append(errs, j.location, err)
		}
		pkgs = append(pkgs, nestedPkgs...)
		relationships = append(relationships, nestedRelationships...)
	} else {
		// .jar and .war files are present in archives, are others? or generally just consider them top-level?
		nestedArchives := j.fileManifest.GlobMatch(true, "*.jar", "*.war")
		if len(nestedArchives) > 0 {
			slices.Sort(nestedArchives)
			errs = unknown.Appendf(errs, j.location, "nested archives not cataloged: %v", strings.Join(nestedArchives, ", "))
		}
	}

	if len(pkgs) == 0 {
		errs = unknown.Appendf(errs, j.location, "no package identified in archive")
	}

	return pkgs, relationships, errs
}

// finalizePackage potentially updates some package information such as classifying the package as a Jenkins plugin,
// sets the PURL, and calls p.SetID()
func finalizePackage(p *pkg.Package) {
	if m, ok := p.Metadata.(pkg.JavaArchive); ok {
		p.PURL = packageURL(p.Name, p.Version, m)

		if strings.Contains(p.PURL, "io.jenkins.plugins") || strings.Contains(p.PURL, "org.jenkins-ci.plugins") {
			p.Type = pkg.JenkinsPluginPkg
		}
	} else {
		log.WithFields("package", p.String()).Debug("unable to extract java metadata to generate purl")
	}

	p.SetID()
}

// discoverMainPackage parses the root Java manifest used as the parent package to all discovered nested packages.
func (j *archiveParser) discoverMainPackage(ctx context.Context) (*pkg.Package, error) {
	// search and parse java manifest files
	manifestMatches := j.fileManifest.GlobMatch(false, manifestGlob)
	if len(manifestMatches) > 1 {
		return nil, fmt.Errorf("found multiple manifests in the jar: %+v", manifestMatches)
	} else if len(manifestMatches) == 0 {
		// we did not find any manifests, but that may not be a problem (there may be other information to generate packages for)
		return nil, nil
	}

	// fetch the manifest file
	contents, err := intFile.ContentsFromZip(ctx, j.archivePath, manifestMatches...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract java manifests (%s): %w", j.location, err)
	}

	// parse the manifest file into a rich object
	manifestContents := contents[manifestMatches[0]]
	manifest, err := parseJavaManifest(j.archivePath, strings.NewReader(manifestContents))
	if err != nil {
		log.Debugf("failed to parse java manifest (%s): %+v", j.location, err)
		return nil, nil
	}

	// check for existence of Weave-Classes manifest key in order to exclude jars getting misrepresented as
	// their targeted counterparts, e.g. newrelic spring and tomcat instrumentation
	if _, ok := manifest.Main.Get("Weave-Classes"); ok {
		log.Debugf("excluding archive due to Weave-Classes manifest entry: %s", j.location)
		return nil, nil
	}

	// grab and assign digest for the entire archive
	digests, err := getDigestsFromArchive(ctx, j.archivePath)
	if err != nil {
		return nil, err
	}

	name, version, lics, err := j.discoverNameVersionLicense(ctx, manifest)
	if err != nil {
		return nil, err
	}

	return &pkg.Package{
		// TODO: maybe select name should just have a pom properties in it?
		Name:     name,
		Version:  version,
		Language: pkg.Java,
		Licenses: pkg.NewLicenseSet(lics...),
		Locations: file.NewLocationSet(
			j.location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Type: j.fileInfo.pkgType(),
		Metadata: pkg.JavaArchive{
			VirtualPath:    j.location.Path(),
			Manifest:       manifest,
			ArchiveDigests: digests,
		},
	}, nil
}

func (j *archiveParser) discoverNameVersionLicense(ctx context.Context, manifest *pkg.JavaManifest) (string, string, []pkg.License, error) {
	// we use j.location because we want to associate the license declaration with where we discovered the contents in the manifest
	// TODO: when we support locations of paths within archives we should start passing the specific manifest location object instead of the top jar
	lics := pkg.NewLicensesFromLocationWithContext(ctx, j.location, selectLicenses(manifest)...)
	/*
		We should name and version from, in this order:
		1. pom.properties if we find exactly 1
		2. pom.xml if we find exactly 1
		3. manifest
		4. filename
	*/
	groupID, artifactID, version, parsedPom := j.discoverMainPackageFromPomInfo(ctx)
	if artifactID == "" {
		artifactID = selectName(manifest, j.fileInfo)
	}
	if version == "" {
		version = selectVersion(manifest, j.fileInfo)
	}

	if len(lics) == 0 {
		fileLicenses, err := j.getLicenseFromFileInArchive(ctx)
		if err != nil {
			return "", "", nil, err
		}
		if fileLicenses != nil {
			lics = append(lics, fileLicenses...)
		}
	}

	// If we didn't find any licenses in the archive so far, we'll try again in Maven Central using groupIDFromJavaMetadata
	if len(lics) == 0 {
		// Today we don't have a way to distinguish between licenses from the manifest and licenses from the pom.xml
		// until the file.Location object can support sub-paths (i.e. paths within archives, recursively; issue https://github.com/anchore/syft/issues/2211).
		// Until then it's less confusing to use the licenses from the pom.xml only if the manifest did not list any.
		lics = j.findLicenseFromJavaMetadata(ctx, groupID, artifactID, version, parsedPom, manifest)
	}

	return artifactID, version, lics, nil
}

// findLicenseFromJavaMetadata attempts to find license information from all available maven metadata properties and pom info
func (j *archiveParser) findLicenseFromJavaMetadata(ctx context.Context, groupID, artifactID, version string, parsedPom *parsedPomProject, manifest *pkg.JavaManifest) []pkg.License {
	if groupID == "" {
		if gID := groupIDFromJavaMetadata(artifactID, pkg.JavaArchive{Manifest: manifest}); gID != "" {
			groupID = gID
		}
	}

	var err error
	var pomLicenses []maven.License
	if parsedPom != nil {
		pomLicenses, err = j.maven.ResolveLicenses(ctx, parsedPom.project)
		if err != nil {
			log.WithFields("error", err, "mavenID", j.maven.ResolveID(ctx, parsedPom.project)).Trace("error attempting to resolve pom licenses")
		}
	}

	if err == nil && len(pomLicenses) == 0 {
		pomLicenses, err = j.maven.FindLicenses(ctx, groupID, artifactID, version)
		if err != nil {
			log.WithFields("error", err, "mavenID", maven.NewID(groupID, artifactID, version)).Trace("error attempting to find licenses")
		}
	}

	if len(pomLicenses) == 0 {
		// Try removing the last part of the groupId, as sometimes it duplicates the artifactId
		packages := strings.Split(groupID, ".")
		groupID = strings.Join(packages[:len(packages)-1], ".")
		pomLicenses, err = j.maven.FindLicenses(ctx, groupID, artifactID, version)
		if err != nil {
			log.WithFields("error", err, "mavenID", maven.NewID(groupID, artifactID, version)).Trace("error attempting to find sub-group licenses")
		}
	}

	return toPkgLicenses(ctx, &j.location, pomLicenses)
}

func toPkgLicenses(ctx context.Context, location *file.Location, licenses []maven.License) []pkg.License {
	var out []pkg.License
	for _, license := range licenses {
		name := ""
		if license.Name != nil {
			name = *license.Name
		}
		url := ""
		if license.URL != nil {
			url = *license.URL
		}
		// note: it is possible to:
		// - have a license without a URL
		// - have license and a URL
		// - have a URL without a license (this is weird, but can happen)
		if name == "" && url == "" {
			continue
		}
		out = append(out, pkg.NewLicenseFromFieldsWithContext(ctx, name, url, location))
	}
	return out
}

type parsedPomProject struct {
	path    string
	project *maven.Project
}

// discoverMainPackageFromPomInfo attempts to resolve maven groupId, artifactId, version and other info from found pom information
func (j *archiveParser) discoverMainPackageFromPomInfo(ctx context.Context) (group, name, version string, parsedPom *parsedPomProject) {
	var pomProperties pkg.JavaPomProperties

	// Find the pom.properties/pom.xml if the names seem like a plausible match
	properties, _ := pomPropertiesByParentPath(ctx, j.archivePath, j.location, j.fileManifest.GlobMatch(false, pomPropertiesGlob))
	projects, _ := pomProjectByParentPath(ctx, j.archivePath, j.location, j.fileManifest.GlobMatch(false, pomXMLGlob))

	// map of all the artifacts in the pom properties, in order to chek exact match with the filename
	artifactsMap := make(map[string]bool)
	for _, propertiesObj := range properties {
		artifactsMap[propertiesObj.ArtifactID] = true
	}

	parentPaths := maps.Keys(properties)
	slices.Sort(parentPaths)
	for _, parentPath := range parentPaths {
		propertiesObj := properties[parentPath]
		if artifactIDMatchesFilename(propertiesObj.ArtifactID, j.fileInfo.name, artifactsMap) {
			pomProperties = propertiesObj
			if proj, exists := projects[parentPath]; exists {
				parsedPom = proj
				break
			}
		}
	}

	group = pomProperties.GroupID
	name = pomProperties.ArtifactID
	version = pomProperties.Version

	if parsedPom != nil && parsedPom.project != nil {
		id := j.maven.ResolveID(ctx, parsedPom.project)
		if group == "" {
			group = id.GroupID
		}
		if name == "" {
			name = id.ArtifactID
		}
		if version == "" {
			version = id.Version
		}
	}

	return group, name, version, parsedPom
}

func artifactIDMatchesFilename(artifactID, fileName string, artifactsMap map[string]bool) bool {
	if artifactID == "" || fileName == "" {
		return false
	}
	// Ensure true is returned when filename matches the artifact ID, prevent random retrieval by checking prefix and suffix
	if _, exists := artifactsMap[fileName]; exists {
		return artifactID == fileName
	}
	// Use fallback check with suffix and prefix if no POM properties file matches the exact artifact name
	return strings.HasPrefix(artifactID, fileName) || strings.HasSuffix(fileName, artifactID)
}

// discoverPkgsFromAllMavenFiles parses Maven POM properties/xml for a given
// parent package, returning all listed Java packages found for each pom
// properties discovered and potentially updating the given parentPkg with new
// data.
func (j *archiveParser) discoverPkgsFromAllMavenFiles(ctx context.Context, parentPkg *pkg.Package) ([]pkg.Package, error) {
	if parentPkg == nil {
		return nil, nil
	}

	var pkgs []pkg.Package

	// pom.properties
	properties, err := pomPropertiesByParentPath(ctx, j.archivePath, j.location, j.fileManifest.GlobMatch(false, pomPropertiesGlob))
	if err != nil {
		return nil, err
	}

	// pom.xml
	projects, err := pomProjectByParentPath(ctx, j.archivePath, j.location, j.fileManifest.GlobMatch(false, pomXMLGlob))
	if err != nil {
		return nil, err
	}

	for parentPath, propertiesObj := range properties {
		var parsedPom *parsedPomProject
		if proj, exists := projects[parentPath]; exists {
			parsedPom = proj
		}

		pkgFromPom := newPackageFromMavenData(ctx, j.maven, propertiesObj, parsedPom, parentPkg, j.location)
		if pkgFromPom != nil {
			pkgs = append(pkgs, *pkgFromPom)
		}
	}

	return pkgs, nil
}

func getDigestsFromArchive(ctx context.Context, archivePath string) ([]file.Digest, error) {
	archiveCloser, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open archive path (%s): %w", archivePath, err)
	}
	defer internal.CloseAndLogError(archiveCloser, archivePath)

	// grab and assign digest for the entire archive
	digests, err := intFile.NewDigestsFromFile(ctx, archiveCloser, javaArchiveHashes)
	if err != nil {
		log.Debugf("failed to create digest for file=%q: %+v", archivePath, err)
	}

	return digests, nil
}

func (j *archiveParser) getLicenseFromFileInArchive(ctx context.Context) ([]pkg.License, error) {
	var out []pkg.License
	for _, filename := range licenses.FileNames() {
		licenseMatches := j.fileManifest.GlobMatch(true, "/META-INF/"+filename)
		if len(licenseMatches) == 0 {
			// Try the root directory if it's not in META-INF
			licenseMatches = j.fileManifest.GlobMatch(true, "/"+filename)
		}

		if len(licenseMatches) > 0 {
			contents, err := intFile.ContentsFromZip(ctx, j.archivePath, licenseMatches...)
			if err != nil {
				return nil, fmt.Errorf("unable to extract java license (%s): %w", j.location, err)
			}

			for _, licenseMatch := range licenseMatches {
				licenseContents := contents[licenseMatch]
				r := strings.NewReader(licenseContents)
				lics := pkg.NewLicensesFromReadCloserWithContext(ctx, file.NewLocationReadCloser(j.location, io.NopCloser(r)))
				if len(lics) > 0 {
					out = append(out, lics...)
				}
			}
		}
	}

	return out, nil
}

func (j *archiveParser) discoverPkgsFromNestedArchives(ctx context.Context, parentPkg *pkg.Package) ([]pkg.Package, []artifact.Relationship, error) {
	// we know that all java archives are zip formatted files, so we can use the shared zip helper
	return discoverPkgsFromZip(ctx, j.location, j.archivePath, j.contentPath, j.fileManifest, parentPkg, j.cfg)
}

// discoverPkgsFromZip finds Java archives within Java archives, returning all listed Java packages found and
// associating each discovered package to the given parent package.
func discoverPkgsFromZip(ctx context.Context, location file.Location, archivePath, contentPath string, fileManifest intFile.ZipFileManifest, parentPkg *pkg.Package, cfg ArchiveCatalogerConfig) ([]pkg.Package, []artifact.Relationship, error) {
	// search and parse pom.properties files & fetch the contents
	openers, err := intFile.ExtractFromZipToUniqueTempFile(ctx, archivePath, contentPath, fileManifest.GlobMatch(false, archiveFormatGlobs...)...)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to extract files from zip: %w", err)
	}

	return discoverPkgsFromOpeners(ctx, location, openers, parentPkg, cfg)
}

// discoverPkgsFromOpeners finds Java archives within the given files and associates them with the given parent package.
func discoverPkgsFromOpeners(ctx context.Context, location file.Location, openers map[string]intFile.Opener, parentPkg *pkg.Package, cfg ArchiveCatalogerConfig) ([]pkg.Package, []artifact.Relationship, error) {
	var pkgs []pkg.Package
	var relationships []artifact.Relationship

	for pathWithinArchive, archiveOpener := range openers {
		nestedPkgs, nestedRelationships, err := discoverPkgsFromOpener(ctx, location, pathWithinArchive, archiveOpener, cfg, parentPkg)
		if err != nil {
			log.WithFields("location", location.Path(), "error", err).Debug("unable to discover java packages from opener")
			continue
		}

		// attach the parent package to all discovered packages that are not already associated with a java archive
		for _, p := range nestedPkgs {
			if metadata, ok := p.Metadata.(pkg.JavaArchive); ok {
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
func discoverPkgsFromOpener(ctx context.Context, location file.Location, pathWithinArchive string, archiveOpener intFile.Opener, cfg ArchiveCatalogerConfig, parentPkg *pkg.Package) ([]pkg.Package, []artifact.Relationship, error) {
	archiveReadCloser, err := archiveOpener.Open()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to open archived file from tempdir: %w", err)
	}
	defer func() {
		if closeErr := archiveReadCloser.Close(); closeErr != nil {
			log.Debugf("unable to close archived file from tempdir: %+v", closeErr)
		}
	}()

	nestedPath := fmt.Sprintf("%s:%s", location.Path(), pathWithinArchive)
	nestedLocation := file.NewLocationFromCoordinates(location.Coordinates)
	nestedLocation.AccessPath = nestedPath
	gap := newGenericArchiveParserAdapter(cfg)
	nestedPkgs, nestedRelationships, err := gap.processJavaArchive(ctx, file.LocationReadCloser{
		Location:   nestedLocation,
		ReadCloser: archiveReadCloser,
	}, parentPkg)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to process nested java archive (%s): %w", pathWithinArchive, err)
	}

	return nestedPkgs, nestedRelationships, nil
}

func pomPropertiesByParentPath(ctx context.Context, archivePath string, location file.Location, extractPaths []string) (map[string]pkg.JavaPomProperties, error) {
	contentsOfMavenPropertiesFiles, err := intFile.ContentsFromZip(ctx, archivePath, extractPaths...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract maven files: %w", err)
	}

	propertiesByParentPath := make(map[string]pkg.JavaPomProperties)
	for filePath, fileContents := range contentsOfMavenPropertiesFiles {
		pomProperties, err := parsePomProperties(filePath, strings.NewReader(fileContents))
		if err != nil {
			log.WithFields("contents-path", filePath, "location", location.Path(), "error", err).Debug("failed to parse pom.properties")
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

func pomProjectByParentPath(ctx context.Context, archivePath string, location file.Location, extractPaths []string) (map[string]*parsedPomProject, error) {
	contentsOfMavenProjectFiles, err := intFile.ContentsFromZip(ctx, archivePath, extractPaths...)
	if err != nil {
		return nil, fmt.Errorf("unable to extract maven files: %w", err)
	}

	projectByParentPath := make(map[string]*parsedPomProject)
	for filePath, fileContents := range contentsOfMavenProjectFiles {
		// TODO: when we support locations of paths within archives we should start passing the specific pom.xml location object instead of the top jar
		pom, err := maven.ParsePomXML(strings.NewReader(fileContents))
		if err != nil {
			log.WithFields("contents-path", filePath, "location", location.Path(), "error", err).Debug("failed to parse pom.xml")
			continue
		}
		if pom == nil {
			continue
		}

		projectByParentPath[path.Dir(filePath)] = &parsedPomProject{
			path:    filePath,
			project: pom,
		}
	}
	return projectByParentPath, nil
}

// newPackageFromMavenData processes a single Maven POM properties for a given parent package, returning all listed Java packages found and
// associating each discovered package to the given parent package. Note the pom.xml is optional, the pom.properties is not.
func newPackageFromMavenData(ctx context.Context, r *maven.Resolver, pomProperties pkg.JavaPomProperties, parsedPom *parsedPomProject, parentPkg *pkg.Package, location file.Location) *pkg.Package {
	// keep the artifact name within the virtual path if this package does not match the parent package
	vPathSuffix := ""
	groupID := ""
	if parentMetadata, ok := parentPkg.Metadata.(pkg.JavaArchive); ok {
		groupID = groupIDFromJavaMetadata(parentPkg.Name, parentMetadata)
	}

	parentKey := fmt.Sprintf("%s:%s:%s", groupID, parentPkg.Name, parentPkg.Version)
	// Since we don't have a package yet, it's important to use the same `field: value` association that we used when creating the parent package
	// See below where Name => pomProperties.ArtifactID and Version => pomProperties.Version. We want to check for potentially nested identical
	// packages and create equal virtual paths so they are de duped in the future
	pomProjectKey := fmt.Sprintf("%s:%s:%s", pomProperties.GroupID, pomProperties.ArtifactID, pomProperties.Version)
	if parentKey != pomProjectKey {
		// build a new virtual path suffix for the package that is different from the parent package
		// we want to use the GroupID and ArtifactID here to preserve uniqueness
		// Some packages have the same name but different group IDs (e.g. "org.glassfish.jaxb/jaxb-core", "com.sun.xml.bind/jaxb-core")
		// https://github.com/anchore/syft/issues/1944
		vPathSuffix += ":" + pomProperties.GroupID + ":" + pomProperties.ArtifactID
	}
	virtualPath := location.Path() + vPathSuffix

	var pkgPomProject *pkg.JavaPomProject

	var err error
	var pomLicenses []maven.License
	if parsedPom == nil {
		// If we have no pom.xml, check maven central using pom.properties
		pomLicenses, err = r.FindLicenses(ctx, pomProperties.GroupID, pomProperties.ArtifactID, pomProperties.Version)
	} else {
		pkgPomProject = newPomProject(ctx, r, parsedPom.path, parsedPom.project)
		pomLicenses, err = r.ResolveLicenses(ctx, parsedPom.project)
	}

	if err != nil {
		log.WithFields("error", err, "mavenID", maven.NewID(pomProperties.GroupID, pomProperties.ArtifactID, pomProperties.Version)).Trace("error attempting to resolve licenses")
	}

	licenseSet := pkg.NewLicenseSet(toPkgLicenses(ctx, &location, pomLicenses)...)

	p := pkg.Package{
		Name:    pomProperties.ArtifactID,
		Version: pomProperties.Version,
		Locations: file.NewLocationSet(
			location.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation),
		),
		Licenses: licenseSet,
		Language: pkg.Java,
		Type:     pomProperties.PkgTypeIndicated(),
		Metadata: pkg.JavaArchive{
			VirtualPath:   virtualPath,
			PomProperties: &pomProperties,
			PomProject:    pkgPomProject,
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
	metadata, ok := p.Metadata.(pkg.JavaArchive)
	parentMetadata, parentOk := parentPkg.Metadata.(pkg.JavaArchive)
	if !ok || !parentOk {
		switch {
		case !ok:
			log.WithFields("package", p.String()).Trace("unable to extract java metadata to check for matching package identity for package: %s", p.Name)
		case !parentOk:
			log.WithFields("package", parentPkg.String()).Trace("unable to extract java metadata to check for matching package identity for package: %s", parentPkg.Name)
		}
		// if we can't extract metadata, we can check for matching identities via the package name
		// this is not ideal, but it's better than nothing - this should not be used if we have Metadata

		return uniquePkgKey("", &p) == uniquePkgKey("", parentPkg)
	}

	// try to determine identity with the metadata
	groupID := groupIDFromJavaMetadata(p.Name, metadata)
	parentGroupID := groupIDFromJavaMetadata(parentPkg.Name, parentMetadata)
	if uniquePkgKey(groupID, &p) == uniquePkgKey(parentGroupID, parentPkg) {
		return true
	}

	// the virtual path matches...
	if parentMetadata.VirtualPath == metadata.VirtualPath {
		return true
	}

	// the pom artifactId is the parent name
	// note: you CANNOT use name-is-subset-of-artifact-id or vice versa --this is too generic. Shaded jars are a good
	// example of this: where the package name is "cloudbees-analytics-segment-driver" and a child is "analytics", but
	// they do not indicate the same package.
	// NOTE: artifactId might not be a good indicator of uniqueness since archives can contain forks with the same name
	// from different groups (e.g. "org.glassfish.jaxb.jaxb-core" and "com.sun.xml.bind.jaxb-core")
	// we will use this check as a last resort
	if metadata.PomProperties != nil {
		if metadata.PomProperties.ArtifactID != "" && parentPkg.Name == metadata.PomProperties.ArtifactID {
			return true
		}
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

	metadata, ok := p.Metadata.(pkg.JavaArchive)
	if !ok {
		return
	}
	pomPropertiesCopy := *metadata.PomProperties

	// keep the pom properties, but don't overwrite existing pom properties
	parentMetadata, ok := parentPkg.Metadata.(pkg.JavaArchive)
	if ok && parentMetadata.PomProperties == nil {
		parentMetadata.PomProperties = &pomPropertiesCopy
		parentPkg.Metadata = parentMetadata
	}
}
