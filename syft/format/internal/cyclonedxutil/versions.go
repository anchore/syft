package cyclonedxutil

import (
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/CycloneDX/cyclonedx-go"

	"github.com/anchore/syft/syft/sbom"
)

const (
	XMLFormatID  sbom.FormatID = "cyclonedx-xml"
	JSONFormatID sbom.FormatID = "cyclonedx-json"
)

const DefaultVersion = "1.7"

var commonVersions = map[string]cyclonedx.SpecVersion{
	"1.2":          cyclonedx.SpecVersion1_2,
	"1.3":          cyclonedx.SpecVersion1_3,
	"1.4":          cyclonedx.SpecVersion1_4,
	"1.5":          cyclonedx.SpecVersion1_5,
	"1.6":          cyclonedx.SpecVersion1_6,
	DefaultVersion: cyclonedx.SpecVersion1_7,
}

var allVersions = func() map[string]cyclonedx.SpecVersion {
	out := map[string]cyclonedx.SpecVersion{
		"1.0": cyclonedx.SpecVersion1_0,
		"1.1": cyclonedx.SpecVersion1_1,
	}
	maps.Copy(out, commonVersions)
	return out
}()

func SupportedVersions(id sbom.FormatID) []string {
	versionSet := commonVersions
	if id == XMLFormatID {
		versionSet = allVersions
	}
	versions := make([]string, 0, len(versionSet))
	for _, v := range versionSet {
		versions = append(versions, v.String())
	}
	slices.SortFunc(versions, versionSort)
	return versions
}

func SpecVersionFromString(v string) (cyclonedx.SpecVersion, error) {
	if specVersion, ok := allVersions[v]; ok {
		return specVersion, nil
	}
	return -1, fmt.Errorf("unsupported CycloneDX version %q", v)
}

func VersionFromSpecVersion(spec cyclonedx.SpecVersion) string {
	for version, specVersion := range allVersions {
		if specVersion == spec {
			return version
		}
	}
	return ""
}

func versionSort(a string, b string) int {
	partsA := strings.Split(a, ".")
	partsB := strings.Split(b, ".")
	lenA := len(partsA)
	lenB := len(partsB)
	for i := range max(lenA, lenB) {
		if i >= lenA {
			return -1 // 1 < 1.x
		}
		if i >= lenB {
			return 1 // 1.x > 1
		}
		partA, errA := strconv.ParseInt(partsA[i], 10, 64)
		partB, errB := strconv.ParseInt(partsB[i], 10, 64)
		if errA != nil || errB != nil {
			// string compare if we can't parse one of the sides
			strcmp := strings.Compare(partsA[i], partsB[i])
			if strcmp == 0 {
				continue
			}
			return strcmp // not equal
		}
		if partA == partB {
			continue
		}
		return int(partA - partB)
	}
	return 0
}
