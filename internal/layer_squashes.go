package internal

import "context"

type eagerLayerSquashesKey struct{}

// WithEagerLayerSquashes has the image source provider build every layer's squashed tree while it reads the
// image, instead of the first time each one is used. Set it when the scan will read lower layers (any scope but
// squashed): eager squashing overlaps with fetching and indexing the layers, so those scans finish sooner.
func WithEagerLayerSquashes(ctx context.Context) context.Context {
	return context.WithValue(ctx, eagerLayerSquashesKey{}, true)
}

func EagerLayerSquashes(ctx context.Context) bool {
	v, _ := ctx.Value(eagerLayerSquashesKey{}).(bool)
	return v
}
