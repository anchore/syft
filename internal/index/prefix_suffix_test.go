package index

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_PrefixSuffix(t *testing.T) {
	i := PrefixSuffix[int]{}
	i.Set("one", 1)
	i.Set("once", 11)
	i.Set("onesie", 111)
	i.Set("two", 2)
	i.Set("done", 99)
	require.Equal(t, 1, i.Get("one"))
	require.Equal(t, 11, i.Get("once"))
	require.Equal(t, 111, i.Get("onesie"))
	require.Equal(t, 2, i.Get("two"))
	requireHasAll(t, i.ByPrefix("on"), 1, 11, 111)
	requireHasAll(t, i.BySuffix("e"), 1, 11, 111, 99)
	requireHasAll(t, i.BySuffix(""), 1, 2, 11, 111, 99)
	requireHasAll(t, i.BySuffix("one"), 1, 99)
	requireHasAll(t, i.BySuffix("sie"), 111)
}

func Test_reverse(t *testing.T) {
	require.Equal(t, "case", reverse("esac"))
}
