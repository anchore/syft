package licenses

// all of these taken from https://github.com/golang/pkgsite/blob/8996ff632abee854aef1b764ca0501f262f8f523/internal/licenses/licenses.go#L338
// which unfortunately is not exported. But fortunately is under BSD-style license. Take note that this list has
// been manually updated to include more license filenames (see https://github.com/anchore/syft/pull/2227).

func FileNames() []string {
	return []string{
		"AL2.0",
		"COPYING",
		"COPYING.md",
		"COPYING.markdown",
		"COPYING.txt",
		"LGPL2.1",
		"LICENCE",
		"LICENCE.md",
		"LICENCE.markdown",
		"licence.txt",
		"LICENCE.txt",
		"LICENSE",
		"LICENSE.md",
		"LICENSE.markdown",
		"LICENSE.txt",
		"LICENSE-2.0.txt",
		"LICENCE-2.0.txt",
		"LICENSE-APACHE",
		"LICENCE-APACHE",
		"LICENSE-APACHE-2.0.txt",
		"LICENCE-APACHE-2.0.txt",
		"LICENSE-MIT",
		"LICENCE-MIT",
		"LICENSE.MIT",
		"LICENCE.MIT",
		"LICENSE.code",
		"LICENCE.code",
		"LICENSE.docs",
		"LICENCE.docs",
		"LICENSE.rst",
		"LICENCE.rst",
		"MIT-LICENSE",
		"MIT-LICENCE",
		"MIT-LICENSE.md",
		"MIT-LICENCE.md",
		"MIT-LICENSE.markdown",
		"MIT-LICENCE.markdown",
		"MIT-LICENSE.txt",
		"MIT-LICENCE.txt",
		"MIT_LICENSE",
		"MIT_LICENCE",
		"UNLICENSE",
		"UNLICENCE",
	}
}
