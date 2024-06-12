package cache

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func Test_Resolver(t *testing.T) {
	original := GetManager()
	defer SetManager(original)
	SetManager(NewInMemory(time.Hour))

	type sub struct {
		Name  string
		Value bool
	}

	type thing struct {
		Value  string
		Values []int
		Subs   []*sub
	}

	versionHash := hashType[thing]()
	cache := GetManager().GetCache("test", "v7/"+versionHash)

	resolver := GetResolver[thing]("test", "v7")
	require.NotNil(t, resolver)

	require.IsType(t, &cacheResolver[thing]{}, resolver)
	cr := resolver.(*cacheResolver[thing])

	require.IsType(t, cache, cr.cache)

	resolveErrCount := 0
	resolveThingErr := func() (thing, error) {
		resolveErrCount++
		return thing{}, fmt.Errorf("an error")
	}

	_, err := resolver.Resolve("err", resolveThingErr)
	require.ErrorContains(t, err, "an error")
	require.Equal(t, 1, resolveErrCount)

	_, err = resolver.Resolve("err", resolveThingErr)
	require.ErrorContains(t, err, "an error")
	require.Equal(t, 2, resolveErrCount)

	aThing := thing{
		Value:  "a value",
		Values: []int{7, 8, 9},
		Subs: []*sub{
			{
				Name:  "sub1",
				Value: true,
			},
			{
				Name:  "sub2",
				Value: false,
			},
		},
	}

	resolveThingCount := 0
	resolveThing := func() (thing, error) {
		resolveThingCount++
		return aThing, nil
	}

	val, err := resolver.Resolve("thing", resolveThing)
	require.NoError(t, err)
	require.Equal(t, 1, resolveThingCount)
	require.Equal(t, aThing, val)

	val, err = resolver.Resolve("thing", resolveThing)
	require.NoError(t, err)
	require.Equal(t, 1, resolveThingCount)
	require.Equal(t, aThing, val)

	rdr, err := cache.Read("thing" + resolverKeySuffix)
	require.NoError(t, err)
	decoder := json.NewDecoder(rdr)

	var val2 thing
	err = decoder.Decode(&val2)
	require.NoError(t, err)
	require.Equal(t, aThing, val2)
}
