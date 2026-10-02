package index

// PrefixSuffix index combines two KeySplitIndexes to simplify indexing and searching by prefix and suffix
type PrefixSuffix[T any] struct {
	forwardIndex KeySplitIndex[T]
	reverseIndex KeySplitIndex[T]
}

func (f *PrefixSuffix[T]) Set(key string, value T) {
	f.forwardIndex.Set(key, value)
	f.reverseIndex.Set(reverse(key), value)
}

func (f *PrefixSuffix[T]) Update(key string, fn NodeUpdateFunc[T]) {
	f.forwardIndex.Update(key, fn)
	f.reverseIndex.Update(reverse(key), fn)
}

func (f *PrefixSuffix[T]) Get(key string) T {
	return f.forwardIndex.Get(key)
}

func (f *PrefixSuffix[T]) ByPrefix(prefix string) []T {
	return f.forwardIndex.ByPrefix(prefix)
}

func (f *PrefixSuffix[T]) BySuffix(suffix string) []T {
	return f.reverseIndex.ByPrefix(reverse(suffix))
}

func reverse(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
