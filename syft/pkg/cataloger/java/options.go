package java

type JavaCatalogerOpts struct {
	SearchMavenForLicenses bool
}

func (j JavaCatalogerOpts) WithSearchMavenForLicenses(input bool) JavaCatalogerOpts {
	j.SearchMavenForLicenses = input
	return j
}

func NewJavaCatalogerOpts() JavaCatalogerOpts {
	return JavaCatalogerOpts{
		SearchMavenForLicenses: false,
	}
}
