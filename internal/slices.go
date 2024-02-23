package internal

// Map maps each value to a function call, returning a new slice of returned types
func Map[From any, To any](values []From, fn func(From) To) []To {
	out := make([]To, len(values))
	for i := range values {
		out[i] = fn(values[i])
	}
	return out
}

// Remove returns a new slice with elements removed indicated by a true return value from the removeFunc call
func Remove[T any](values []T, removeFunc func(T) bool) []T {
	var out []T
	for _, t := range values {
		if removeFunc(t) {
			continue
		}
		out = append(out, t)
	}
	return out
}
