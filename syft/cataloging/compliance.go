package cataloging

import (
	"strings"
)

const (
	ComplianceActionKeep ComplianceAction = "keep"
	ComplianceActionDrop ComplianceAction = "drop"
	ComplianceActionStub ComplianceAction = "stub"
)

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
	case string(ComplianceActionDrop), "exclude":
		return ComplianceActionDrop
	case string(ComplianceActionStub), "replace":
		return ComplianceActionStub
	}
	return ComplianceActionKeep
}
