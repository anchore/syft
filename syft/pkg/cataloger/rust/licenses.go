package rust

type rustCratesLicenseResolver struct{}

func newCratesLicenseResolver(name string, opts CatalogerConfig) *rustCratesLicenseResolver {
	return &rustCratesLicenseResolver{}
}
