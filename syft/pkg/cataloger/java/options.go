package java

type CatalogerOpts struct {
	SearchMavenForLicenses bool
}

func (j CatalogerOpts) WithSearchMavenForLicenses(input bool) CatalogerOpts {
	j.SearchMavenForLicenses = input
	return j
}

func NewJavaCatalogerOpts() CatalogerOpts {
	return CatalogerOpts{
		SearchMavenForLicenses: false,
	}
}
