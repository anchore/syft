package source

// Option is used when constructing new Source objects
type Option func(*Source)

func WithName(name string) Option {
	return func(s *Source) {
		s.Metadata.Name = name
	}
}

func WithVersion(version string) Option {
	return func(s *Source) {
		s.Metadata.Version = version
	}
}

func WithExclusions(exclusions []string) Option {
	return func(s *Source) {
		s.Exclusions = exclusions
	}
}

func WithBasePath(base string) Option {
	return func(s *Source) {
		s.base = base
		s.Metadata.Base = base
	}
}

// InputOption is used during ParseUserInput
type InputOption func(*Input)

func WithPlatform(platform string) InputOption {
	return func(input *Input) {
		input.Platform = platform
	}
}

func WithDefaultImageSource(defaultImageSource string) InputOption {
	return func(input *Input) {
		input.ImageSource = parseDefaultImageSource(defaultImageSource)
	}
}
