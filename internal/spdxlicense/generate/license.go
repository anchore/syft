package main

import (
	"strings"

	"github.com/scylladb/go-set/strset"
)

type LicenseList struct {
	Version  string    `json:"licenseListVersion"`
	Licenses []License `json:"licenses"`
}

type License struct {
	ID          string   `json:"licenseId"`
	Name        string   `json:"name"`
	Text        string   `json:"licenseText"`
	Deprecated  bool     `json:"isDeprecatedLicenseId"`
	OSIApproved bool     `json:"isOsiApproved"`
	SeeAlso     []string `json:"seeAlso"`
}

func (l License) canReplace(other License) bool {
	if l.Deprecated {
		return false
	}

	if l.Name != other.Name {
		return false
	}

	if l.OSIApproved != other.OSIApproved {
		return false
	}

	if len(l.SeeAlso) != len(other.SeeAlso) {
		return false
	}

	for i, sa := range l.SeeAlso {
		if sa != other.SeeAlso[i] {
			return false
		}
	}

	return l.ID != other.ID
}

func (ll LicenseList) findReplacementLicense(deprecated License) *License {
	for _, l := range ll.Licenses {
		if l.canReplace(deprecated) {
			return &l
		}
	}

	return nil
}

func buildLicensePermutations(license string) (perms []string) {
	lv := findLicenseVersion(license)
	vp := versionPermutations(lv)

	version := strings.Join(lv, ".")
	for _, p := range vp {
		perms = append(perms, strings.Replace(license, version, p, 1))
	}

	return perms
}

func findLicenseVersion(license string) (version []string) {
	versionList := versionMatch.FindAllStringSubmatch(license, -1)

	if len(versionList) == 0 {
		return version
	}

	for i, v := range versionList[0] {
		if v != "" && i != 0 {
			version = append(version, v)
		}
	}

	return version
}

func versionPermutations(version []string) []string {
	ver := append([]string(nil), version...)
	perms := strset.New()
	for i := 1; i <= 3; i++ {
		if len(ver) < i+1 {
			ver = append(ver, "0")
		}

		perm := strings.Join(ver[:i], ".")
		badCount := strings.Count(perm, "0") + strings.Count(perm, ".")

		if badCount != len(perm) {
			perms.Add(perm)
		}
	}

	return perms.List()
}
