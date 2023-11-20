package javascript

type CatalogerOpts struct {
	searchRemoteLicenses bool
}

func (g CatalogerOpts) WithSearchRemoteLicenses(input bool) CatalogerOpts {
	g.searchRemoteLicenses = input
	return g
}

// NewCatalogerOpts create a NewCatalogerOpts with default options, which includes:
// - searchRemoteLicenses is false
func NewCatalogerOpts() CatalogerOpts {
	g := CatalogerOpts{}

	return g
}
