package attestationjson

import "github.com/anchore/syft/syft/format"

func Format() format.Format {
	return format.NewFormat(
		format.AttestationOption,
		encoder,
		nil,
		nil,
	)
}
