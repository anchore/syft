package java

const MavenBaseURL = "https://repo1.maven.org/maven2"

type CatalogerOpts struct {
	SearchMavenForLicenses bool
	MavenURL               string
}

func (j CatalogerOpts) WithSearchMavenForLicenses(input bool) CatalogerOpts {
	j.SearchMavenForLicenses = input
	return j
}

func (j CatalogerOpts) WithMavenCentralURL(input string) CatalogerOpts {
	if input != "" {
		j.MavenURL = input
	}
	return j
}

func DefaultCatalogerOpts() CatalogerOpts {
	return CatalogerOpts{
		SearchMavenForLicenses: false,
		MavenURL:               MavenBaseURL,
	}
}
