package options

import "github.com/anchore/fangs"

type UpdateCheck struct {
	CheckForAppUpdate *bool `yaml:"check-for-app-update" json:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
}

func DefaultUpdateCheck() UpdateCheck {
	return UpdateCheck{}
}

func (cfg *UpdateCheck) DoCheckForAppUpdate(net *Network) bool {
	return *multiLevelOption(true, net.Enabled("update-check"), cfg.CheckForAppUpdate)
}

func (cfg *UpdateCheck) DescribeFields(descriptions fangs.FieldDescriptionSet) {
	descriptions.Add(&cfg.CheckForAppUpdate, "whether to check for an application update on start up or not")
}
