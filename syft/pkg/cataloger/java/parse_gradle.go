package java

import (
	"bufio"
	"regexp"
	"strings"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/pkg/cataloger/generic"
	"github.com/anchore/syft/syft/source"
)

const buildGradleGlob = "*build.gradle*"
const buildGradleDirGlob = "**/build.gradle*"

var propertyMatcherGradle = regexp.MustCompile("[$][{][^}]+[}]")

// Dependency represents a single dependency in the build.gradle file
type Dependency struct {
	Group   string
	Name    string
	Version string
}

// Plugin represents a single plugin in the build.gradle file
type Plugin struct {
	Id      string
	Version string
}

func parserBuildGradle(_ source.FileResolver, _ *generic.Environment, reader source.LocationReadCloser) ([]pkg.Package, []artifact.Relationship, error) {
	//Gradle, err := decodeBuildGradle(reader)
	// if err != nil {
	// 	return nil, nil, err
	// }

	var pkgs []pkg.Package

	// Create a new scanner to read the file
	scanner := bufio.NewScanner(reader)

	// Create slices to hold the dependencies and plugins
	dependencies := []Dependency{}
	plugins := []Plugin{}
	// Create a map to hold the variables
	variables := map[string]string{}

	// Keep track of whether we are in the dependencies or plugins section
	inDependenciesSection := false
	inPluginsSection := false

	// Loop over all lines in the file
	for scanner.Scan() {
		line := scanner.Text()

		// Trim leading and trailing whitespace from the line
		line = strings.TrimSpace(line)

		// Check if the line starts with "dependencies {"
		if strings.HasPrefix(line, "dependencies {") {
			inDependenciesSection = true
			continue
		}

		// Check if the line starts with "plugins {"
		if strings.HasPrefix(line, "plugins {") {
			inPluginsSection = true
			continue
		}

		// Check if the line is "}"
		if line == "}" {
			inDependenciesSection = false
			inPluginsSection = false
			continue
		}

		// Check if we are in the plugins section
		if inPluginsSection {
			// Split the line on whitespace to extract the group, name, and version of the dependency
			fields := strings.Fields(line)
			// Check if the line contains at least 3 fields (group, version as a literal string, and version as the version number)
			if len(fields) >= 3 {
				start := strings.Index(fields[0], "(") + 1
				end := strings.Index(fields[0], ")")
				groupName := fields[0][start:end]
				groupName = strings.Trim(groupName, `"`)
				version := strings.Trim(fields[2], `"`)
				// Create a new Dependency struct and add it to the dependencies slice
				plugin := Plugin{Id: groupName, Version: version}
				plugins = append(plugins, plugin)
			}
		}

		// Check if we are in the dependencies section
		if inDependenciesSection {
			// Extract the group, name, and version from the function call
			start := strings.IndexFunc(line, func(r rune) bool {
				return r == '(' || r == ' '
			}) + 1
			// Extract the group, name, and version from the function call
			end := strings.IndexFunc(line, func(r rune) bool {
				return r == ')' || r == ' '
			})
			groupNameVersion := line[start:end]
			groupNameVersion = strings.Trim(groupNameVersion, "\"")
			parts := strings.Split(groupNameVersion, ":")
			// if we only have 2 sections the version is probably missing
			if len(parts) == 2 {
				// search for the version in the plugin section
				version := searchInPlugins(parts[0], plugins)
				// Create a new Dependency struct and add it to the dependencies slice
				dep := Dependency{Group: parts[0], Name: parts[1], Version: version}
				dependencies = append(dependencies, dep)
			}
			// we have a version directly specified
			if len(parts) == 3 {
				// Create a new Dependency struct and add it to the dependencies slice
				dep := Dependency{Group: parts[0], Name: parts[1], Version: parts[2]}
				dependencies = append(dependencies, dep)
			}
		}

		// Check if the line contains an assignment
		if strings.Contains(line, "=") {
			// Split the line on the "=" character to separate the key and value
			parts := strings.Split(line, "=")

			// Trim any leading and trailing whitespace from the key and value
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])

			// Add the key and value to the map
			variables[key] = value
		}

	}
	// map the dependencies
	for _, dep := range dependencies {
		mappedPkg := pkg.Package{Name: dep.Name, Version: dep.Version}
		pkgs = append(pkgs, mappedPkg)
	}

	return pkgs, nil, nil
}

func searchInPlugins(groupName string, plugins []Plugin) string {
	for _, v := range plugins {
		if v.Id == groupName {
			return v.Version
		}
	}
	return ""
}

// func parseBuildGradleProject(path string, reader io.Reader) (*pkg.GradleProject, error) {
// 	project, err := decodeBuildGradle(reader)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return newGradleProject(path, project), nil
// }

// func newGradleProject(path string, p goGradle.Project) *pkg.GradleProject {
// 	return &pkg.GradleProject{
// 		Path:        path,
// 		Parent:      GradleParent(p, p.Parent),
// 		GroupID:     resolvePropertyGradle(p, p.GroupID),
// 		ArtifactID:  p.ArtifactID,
// 		Version:     resolvePropertyGradle(p, p.Version),
// 		Name:        p.Name,
// 		Description: formatDescription(p.Description),
// 		URL:         p.URL,
// 	}
// }

// func newPackageFromGradle(Gradle goGradle.Project, dep goGradle.Dependency, locations ...source.Location) pkg.Package {
// 	m := pkg.JavaMetadata{
// 		GradleProperties: &pkg.GradleProperties{
// 			GroupID: resolvePropertyGradle(Gradle, dep.GroupID),
// 		},
// 	}

// 	name := dep.ArtifactID
// 	version := resolvePropertyGradle(Gradle, dep.Version)

// 	p := pkg.Package{
// 		Name:         name,
// 		Version:      version,
// 		Locations:    source.NewLocationSet(locations...),
// 		PURL:         packageURL(name, version, m),
// 		Language:     pkg.Java,
// 		Type:         pkg.JavaPkg, // TODO: should we differentiate between packages from jar/war/zip versus packages from a Gradle.xml that were not installed yet?
// 		MetadataType: pkg.JavaMetadataType,
// 		Metadata:     m,
// 	}

// 	p.SetID()

// 	return p
// }

// func decodeBuildGradle(content io.Reader) (project goGradle.Project, err error) {
// 	decoder := xml.NewDecoder(content)
// 	// prevent against warnings for "xml: encoding "iso-8859-1" declared but Decoder.CharsetReader is nil"
// 	decoder.CharsetReader = charset.NewReaderLabel
// 	if err := decoder.Decode(&project); err != nil {
// 		return project, fmt.Errorf("unable to unmarshal Gradle.xml: %w", err)
// 	}

// 	return project, nil
// }

// func GradleParent(Gradle goGradle.Project, parent goGradle.Parent) (result *pkg.GradleParent) {
// 	if parent.ArtifactID != "" || parent.GroupID != "" || parent.Version != "" {
// 		result = &pkg.GradleParent{
// 			GroupID:    resolvePropertyGradle(Gradle, parent.GroupID),
// 			ArtifactID: parent.ArtifactID,
// 			Version:    resolvePropertyGradle(Gradle, parent.Version),
// 		}
// 	}
// 	return result
// }

// func formatDescription(original string) (cleaned string) {
// 	descriptionLines := strings.Split(original, "\n")
// 	for _, line := range descriptionLines {
// 		line = strings.TrimSpace(line)
// 		if len(line) == 0 {
// 			continue
// 		}
// 		cleaned += line + " "
// 	}
// 	return strings.TrimSpace(cleaned)
// }

// // resolvePropertyGradle emulates some maven property resolution logic by looking in the project's variables
// // as well as supporting the project expressions like ${project.parent.groupId}.
// // If no match is found, the entire expression including ${} is returned
// func resolvePropertyGradle(Gradle goGradle.Project, property string) string {
// 	return "1.0.0"
// }
