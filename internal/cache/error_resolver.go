package cache

import "fmt"

// GetResolverCachingErrors returns a Resolver that caches errors and will return them
// instead of continuing to call the provided resolve functions
func GetResolverCachingErrors[T any](name, version string) Resolver[T] {
	return &errorResolver[T]{
		resolver: GetResolver[errResponse[T]](name, version),
	}
}

type errResponse[T any] struct {
	Error string `json:"err,omitempty"`
	Value T      `json:"val,omitempty"`
}

type errorResolver[T any] struct {
	resolver Resolver[errResponse[T]]
}

func (r *errorResolver[T]) Resolve(key string, resolver resolverFunc[T]) (T, error) {
	v, err := r.resolver.Resolve(key, func() (errResponse[T], error) {
		v, err := resolver()
		out := errResponse[T]{
			Value: v,
		}
		if err != nil {
			out.Error = err.Error()
		}
		return out, nil
	})
	if err != nil {
		return v.Value, err
	}
	if v.Error != "" {
		return v.Value, fmt.Errorf(v.Error)
	}
	return v.Value, nil
}
