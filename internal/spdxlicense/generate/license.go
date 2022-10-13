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

	// Some hacks needed until the licenses.json file is updated
	// See https://github.com/spdx/license-list-XML/issues/1676
	if (l.Name == "GNU Lesser General Public License v2.1 or later") && (other.Name == "GNU Library General Public License v2.1 or later") {
        	return true;
	}

	if other.ID == "GFDL-1.1" {
        	return l.ID == "GFDL-1.1-only";
	}

	if other.ID == "GFDL-1.2" {
        	return l.ID == "GFDL-1.2-only";
	}

	if other.ID == "GFDL-1.3" {
		return l.ID == "GFDL-1.3-only";
	}

	if other.ID == "GPL-1.0+" {
		return l.ID == "GPL-1.0-or-later";
	}

	if other.ID == "GPL-2.0+" {
		return l.ID == "GPL-2.0-or-later";
	}

	if other.ID == "GPL-3.0+" {
		return l.ID == "GPL-3.0-or-later";
	}
	if other.ID == "LGPL-2.0+" {
		return l.ID == "LGPL-2.0-or-later";
	}

	if other.ID == "LGPL-2.1+" {
		return l.ID == "LGPL-2.1-or-later";
	}

	if other.ID == "LGPL-3.0+" {
		return l.ID == "LGPL-3.0-or-later";
	}

	if (l.ID == "BSD-2-Clause") && (other.ID == "BSD-2-Clause-NetBSD") {
        	return true;
	}

	if (l.ID == "BSD-2-Clause-Views") && (other.ID == "BSD-2-Clause-FreeBSD") {
		return true;
	}

	if (l.ID == "bzip2-1.0.6") && (other.ID == "bzip2-1.0.5") {
 		return true;
	}

	if l.Name == other.Name {
		return true
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
