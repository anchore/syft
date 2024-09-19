package cataloging

import (
	"sort"
	"strings"
)

const (
	ComplianceActionKeep ComplianceAction = "keep"
	ComplianceActionWarn ComplianceAction = "warn"
	ComplianceActionDrop ComplianceAction = "drop"
	ComplianceActionFail ComplianceAction = "fail"
	ComplianceActionStub ComplianceAction = "stub"
)

type ErrNonCompliantPackages struct {
	NonCompliantPackageLocations map[string][]string
}

func NewErrNonCompliantPackages() *ErrNonCompliantPackages {
	return &ErrNonCompliantPackages{
		NonCompliantPackageLocations: make(map[string][]string),
	}
}

func (e *ErrNonCompliantPackages) AddInfo(location, info, note string) {
	e.NonCompliantPackageLocations[location] = append(e.NonCompliantPackageLocations[location], note+": "+info)
}

func (e ErrNonCompliantPackages) Error() string {
	var reasons []string
	for location, infos := range e.NonCompliantPackageLocations {
		for _, info := range infos {
			reasons = append(reasons, location+": "+info)
		}
	}

	sort.Strings(reasons)

	return "non-compliant packages: " + strings.Join(reasons, "\n")
}

const UnknownStubValue = "UNKNOWN"

type ComplianceAction string

type ComplianceConfig struct {
	MissingName    ComplianceAction `yaml:"missing-name" json:"missing-name" mapstructure:"missing-name"`
	MissingVersion ComplianceAction `yaml:"missing-version" json:"missing-version" mapstructure:"missing-version"`
}

func DefaultComplianceConfig() ComplianceConfig {
	// Note: name and version are required minimum SBOM elements by NTIA, thus should be the API default
	return ComplianceConfig{
		MissingName:    ComplianceActionDrop,
		MissingVersion: ComplianceActionStub,
	}
}

func (c ComplianceConfig) Parse() ComplianceConfig {
	return ComplianceConfig{
		MissingName:    c.MissingName.Parse(),
		MissingVersion: c.MissingVersion.Parse(),
	}
}

func (c ComplianceAction) Parse() ComplianceAction {
	switch strings.ToLower(string(c)) {
	case string(ComplianceActionKeep), "include":
		return ComplianceActionKeep
	case string(ComplianceActionWarn), "warning":
		return ComplianceActionWarn
	case string(ComplianceActionDrop), "exclude":
		return ComplianceActionDrop
	case string(ComplianceActionFail), "error":
		return ComplianceActionFail
	case string(ComplianceActionStub), "replace":
		return ComplianceActionStub
	}
	return ComplianceActionWarn
}
