package source

type sourceOpt struct {
	name               string
	version            string
	platform           string
	defaultImageSource string
	base               string
}
type Option func(*sourceOpt) error

func WithName(name string) Option {
	return func(s *sourceOpt) error {
		s.name = name
		return nil
	}
}

func WithPlatform(platform string) Option {
	return func(s *sourceOpt) error {
		s.platform = platform
		return nil
	}
}

func WithVersion(version string) Option {
	return func(s *sourceOpt) error {
		s.version = version
		return nil
	}
}

func WithDefaultImageSource(defaultImageSource string) Option {
	return func(s *sourceOpt) error {
		s.defaultImageSource = defaultImageSource
		return nil
	}
}

func WithBasePath(base string) Option {
	return func(s *sourceOpt) error {
		s.base = base
		return nil
	}
}
