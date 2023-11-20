package java

const MavenBaseURL = "https://repo1.maven.org/maven2"

type CatalogerOpts struct {
	UseNetwork              bool
	MavenURL                string
	MaxParentRecursiveDepth int
}

func (j CatalogerOpts) WithUseNetwork(input bool) CatalogerOpts {
	j.UseNetwork = input
	return j
}

func (j CatalogerOpts) WithMavenURL(input string) CatalogerOpts {
	if input != "" {
		j.MavenURL = input
	}
	return j
}

func (j CatalogerOpts) WithMaxParentRecursiveDepth(input int) CatalogerOpts {
	if input > 0 {
		j.MaxParentRecursiveDepth = input
	}
	return j
}

func DefaultCatalogerOpts() CatalogerOpts {
	return CatalogerOpts{
		UseNetwork:              false,
		MavenURL:                MavenBaseURL,
		MaxParentRecursiveDepth: 5,
	}
}
