module github.com/anchore/test

go 1.17

require (
	golang.org/x/net v0.0.0-20211006190231-62292e806868
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
)

require golang.org/x/sys v0.0.0-20211006194710-c8a6f5223071 // indirect

exclude golang.org/x/net v0.0.0-20211005215030-d2e5035098b3

replace golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 => golang.org/x/term v0.0.0-20210916214954-140adaaadfaf
