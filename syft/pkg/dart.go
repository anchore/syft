package pkg

import "github.com/anchore/syft/syft/sort"

// DartPubspecLockEntry is a struct that represents a single entry found in the "packages" section in a Dart pubspec.lock file.
type DartPubspecLockEntry struct {
	Name      string `mapstructure:"name" json:"name"`
	Version   string `mapstructure:"version" json:"version"`
	HostedURL string `mapstructure:"hosted_url" json:"hosted_url,omitempty"`
	VcsURL    string `mapstructure:"vcs_url" json:"vcs_url,omitempty"`
}

func (m DartPubspecLockEntry) Compare(other DartPubspecLockEntry) int {
	if i := sort.CompareOrd(m.Name, other.Name); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.Version, other.Version); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.HostedURL, other.HostedURL); i != 0 {
		return i
	}
	if i := sort.CompareOrd(m.VcsURL, other.VcsURL); i != 0 {
		return i
	}
	return 0
}

func (m DartPubspecLockEntry) TryCompare(other any) (bool, int) {
	if other, exists := other.(DartPubspecLockEntry); exists {
		return true, m.Compare(other)
	}
	return false, 0
}
