package helpers

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

type T1 struct {
	Name     string
	Val      int
	ValU     uint
	Flag     bool `json:"bool_flag"`
	Float    float64
	T2       T2
	T2Ptr    *T2
	T2Arr    []T2
	T2PtrArr []*T2
	StrArr   []string
	IntArr   []int
	FloatArr []float64
	BoolArr  []bool
	T3Arr    []T3
}

type T2 struct {
	Name string
}

type T3 struct {
	T4Arr []T4
}

type T4 struct {
	Typ    string
	IntPtr *int
}

type T5 struct {
	Map map[string]string
}

func Test_EncodeDecodeCycle(t *testing.T) {
	val := 99

	tests := []struct {
		name  string
		value interface{}
	}{
		{
			name: "all values",
			value: T1{
				Name:  "name",
				Val:   10,
				ValU:  16,
				Flag:  true,
				Float: 1.2,
				T2: T2{
					Name: "embedded t2",
				},
				T2Ptr: &T2{
					"t2 ptr",
				},
				T2Arr: []T2{
					{"t2 elem 0"},
					{"t2 elem 1"},
				},
				T2PtrArr: []*T2{
					{"t2 ptr v1"},
					{"t2 ptr v2"},
				},
				StrArr:   []string{"s 1", "s 2", "s 3"},
				IntArr:   []int{9, 12, -1},
				FloatArr: []float64{-23.99, 15.234321, 39912342314},
				BoolArr:  []bool{false, true, true, true, false},
				T3Arr: []T3{
					{
						T4Arr: []T4{
							{
								Typ: "t4 nested typ 1",
							},
							{
								Typ:    "t4 nested typ 2",
								IntPtr: &val,
							},
						},
					},
				},
			},
		},
		{
			name: "nil values",
			value: T1{
				Name:     "t1 test",
				Val:      0,
				ValU:     0,
				Flag:     false,
				Float:    0,
				T2:       T2{},
				T2Ptr:    nil,
				T2Arr:    nil,
				T2PtrArr: nil,
				StrArr:   nil,
				IntArr:   nil,
				FloatArr: nil,
				BoolArr:  nil,
				T3Arr:    nil,
			},
		},
		{
			name: "array values",
			value: []T2{
				{"t2 elem 0"},
				{"t2 elem 1"},
			},
		},
		{
			name: "array ptr",
			value: &[]T2{
				{"t2 elem 0"},
				{"t2 elem 1"},
			},
		},
		{
			name: "map of strings",
			value: &T5{
				Map: map[string]string{
					"key1": "value1",
					"key2": "value2",
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			vals := Encode(test.value, "props", OptionalJSONTag)

			typ := reflect.TypeOf(test.value)

			if typ.Kind() != reflect.Slice && typ.Kind() != reflect.Ptr {
				assert.NotEmpty(t, vals["props:bool_flag"])

				t2 := T1{}
				DecodeInto(&t2, vals, "props", OptionalJSONTag)

				assert.EqualValues(t, test.value, t2)
			}

			t3 := Decode(typ, vals, "props", OptionalJSONTag)

			assert.EqualValues(t, test.value, t3)
		})
	}
}
