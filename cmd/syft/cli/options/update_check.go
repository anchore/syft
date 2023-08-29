package options

type UpdateCheck struct {
	CheckForAppUpdate bool `yaml:"check-for-app-update" json:"check-for-app-update" mapstructure:"check-for-app-update"` // whether to check for an application update on start up or not
}

func DefaultUpdateCheck() UpdateCheck {
	return UpdateCheck{
		CheckForAppUpdate: true,
	}
}
