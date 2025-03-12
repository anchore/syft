module github.com/anchore/test

go 1.17

require (
	golang.org/x/net v0.36.0
	golang.org/x/term v0.29.0
)

require golang.org/x/sys v0.30.0 // indirect

exclude golang.org/x/net v0.0.0-20211005215030-d2e5035098b3

replace golang.org/x/term v0.0.0-20210927222741-03fcf44c2211 => golang.org/x/term v0.0.0-20210916214954-140adaaadfaf
