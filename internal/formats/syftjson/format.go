package syftjson

import "github.com/anchore/syft/syft/format"

func Format(appConfig interface{}) format.Format {
	return format.NewFormat(
		format.JSONOption,
		Encoder(appConfig),
		Decoder(),
		Validator(),
	)
}

func Encoder(appConfig interface{}) format.Encoder {
	return &encoder{
		appConfig: appConfig,
	}
}

func Decoder() format.Decoder {
	return &decoder{}
}

func Validator() format.Validator {
	return &validator{}
}
