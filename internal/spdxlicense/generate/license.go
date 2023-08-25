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

// findReplacementLicense returns a replacement license for a deprecated license
func (ll LicenseList) findReplacementLicense(deprecated License) *License {
	for _, l := range ll.Licenses {
		if l.canReplace(deprecated) {
			return &l
		}
	}

	return nil
}

func (l License) canReplace(deprecated License) bool {
	// don't replace a license with a deprecated license
	if l.Deprecated {
		return false
	}

	// We want to replace deprecated licenses with non-deprecated counterparts
	// For more information, see: https://github.com/spdx/license-list-XML/issues/1676
	switch {
	case strings.ReplaceAll(l.ID, "-only", "") == deprecated.ID:
		return true
	case strings.ReplaceAll(l.ID, "-or-later", "+") == deprecated.ID:
		return true
	case l.ID == "BSD-2-Clause" && deprecated.ID == "BSD-2-Clause-NetBSD":
		return true
	case l.ID == "BSD-2-Clause-Views" && deprecated.ID == "BSD-2-Clause-FreeBSD":
		return true
	case l.ID == "bzip2-1.0.6" && deprecated.ID == "bzip2-1.0.5":
		return true
	case l.ID == "SMLNJ" && deprecated.ID == "StandardML-NJ":
		return true
	}

	if l.Name != deprecated.Name {
		return false
	}

	if l.OSIApproved != deprecated.OSIApproved {
		return false
	}

	if len(l.SeeAlso) != len(deprecated.SeeAlso) {
		return false
	}

	for i, sa := range l.SeeAlso {
		if sa != deprecated.SeeAlso[i] {
			return false
		}
	}

	return l.ID == deprecated.ID
}

func buildLicenseIDPermutations(cleanID string) (perms []string) {
	lv := findLicenseVersion(cleanID)
	addPlusPermutation := strings.HasSuffix(cleanID, "orlater")
	vp := versionPermutations(lv)
	permSet := strset.New()
	version := strings.Join(lv, ".")
	for _, p := range vp {
		if addPlusPermutation {
			base := strings.TrimSuffix(cleanID, "orlater")
			plus := p + "+"
			permSet.Add(strings.Replace(base, version, plus, 1))
		}
		permSet.Add(strings.Replace(cleanID, version, p, 1))
	}

	permSet.Add(cleanID)
	return permSet.List()
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
