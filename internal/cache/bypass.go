package cache

import "io"

type bypassedCache struct{}

func (b *bypassedCache) Read(_ string) (ReaderAtCloser, error) {
	return nil, errNotFound
}

func (b *bypassedCache) Write(_ string, contents io.Reader) error {
	if closer, ok := contents.(io.Closer); ok {
		_ = closer.Close()
	}
	return nil
}

func (b *bypassedCache) GetCache(_, _ string) Cache {
	return b
}

func (b *bypassedCache) RootDirs() []string {
	return nil
}
