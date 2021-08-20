package cpe

import "github.com/anchore/syft/syft/pkg"

// this is a static mapping of known package names (keys) to official cpe names for each package
type candidatesByPackageType map[pkg.Type]map[string][]string

func (s candidatesByPackageType) getCandidates(t pkg.Type, key string) []string {
	if _, ok := s[t]; !ok {
		return nil
	}
	value, ok := s[t][key]
	if !ok {
		return nil
	}

	return value
}
