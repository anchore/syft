package binary

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

var (
	// spaceRegex includes nbsp (#160) considered to be a space character
	spaceRegex  = regexp.MustCompile(`[\s\xa0]+`)
	numberRegex = regexp.MustCompile(`\d`)
)

func newPEPackage(versionResources map[string]string, f file.Location) pkg.Package {
	name := findNameFromVR(versionResources)

	if name == "" {
		// it's possible that the version resources are empty, so we fall back to the file name
		name = strings.TrimSuffix(strings.TrimSuffix(path.Base(f.RealPath), ".exe"), ".dll")
	}

	p := pkg.Package{
		Name:      name,
		Version:   findVersionFromVR(versionResources),
		Locations: file.NewLocationSet(f.WithAnnotation(pkg.EvidenceAnnotationKey, pkg.PrimaryEvidenceAnnotation)),
		Type:      pkg.BinaryPkg,
		Metadata:  newPEBinaryVersionResourcesFromMap(versionResources),
	}

	p.SetID()

	return p
}

func newPEBinaryVersionResourcesFromMap(vr map[string]string) pkg.PEBinary {
	var kvs pkg.KeyValues
	for k, v := range vr {
		if v == "" {
			continue
		}
		kvs = append(kvs, pkg.KeyValue{
			Key:   k,
			Value: spaceNormalize(v),
		})
	}

	sort.Slice(kvs, func(i, j int) bool {
		return kvs[i].Key < kvs[j].Key
	})

	return pkg.PEBinary{
		VersionResources: kvs,
	}
}

func findNameFromVR(versionResources map[string]string) string {
	// PE files not authored by Microsoft tend to use ProductName as an identifier.
	nameFields := []string{"ProductName", "FileDescription", "InternalName", "OriginalFilename"}

	if isMicrosoftVR(versionResources) {
		// for Microsoft files, prioritize FileDescription.
		nameFields = []string{"FileDescription", "InternalName", "OriginalFilename", "ProductName"}
	}

	var name string
	for _, field := range nameFields {
		value := spaceNormalize(versionResources[field])
		if value == "" {
			continue
		}
		name = value
		break
	}

	return name
}
func isMicrosoftVR(versionResources map[string]string) bool {
	return strings.Contains(strings.ToLower(versionResources["CompanyName"]), "microsoft") ||
		strings.Contains(strings.ToLower(versionResources["ProductName"]), "microsoft")
}

// spaceNormalize trims and normalizes whitespace in a string.
func spaceNormalize(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	// ensure valid UTF-8.
	value = strings.ToValidUTF8(value, "")
	// consolidate all whitespace.
	value = spaceRegex.ReplaceAllString(value, " ")
	// remove non-printable characters.
	value = regexp.MustCompile(`[\x00-\x1f]`).ReplaceAllString(value, "")
	// consolidate again and trim.
	value = spaceRegex.ReplaceAllString(value, " ")
	value = strings.TrimSpace(value)
	return value
}

func findVersionFromVR(versionResources map[string]string) string {
	productVersion := extractVersionFromResourcesValue(versionResources["ProductVersion"])
	fileVersion := extractVersionFromResourcesValue(versionResources["FileVersion"])

	if productVersion != "" {
		return productVersion
	}

	return fileVersion
}

func extractVersionFromResourcesValue(version string) string {
	version = strings.TrimSpace(version)
	out := ""
	for i, f := range strings.Fields(version) {
		if containsNumber(out) && !containsNumber(f) {
			return out
		}
		if i == 0 {
			out = f
		} else {
			out += " " + f
		}
	}
	return out
}

func containsNumber(s string) bool {
	return numberRegex.MatchString(s)
}
