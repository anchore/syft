package cataloging

type LicenseConfig struct {
	IncludeUnkownLicenseContent bool
}

func DefaultLicenseConfig() LicenseConfig {
	return LicenseConfig{
		IncludeUnkownLicenseContent: false,
	}
}
