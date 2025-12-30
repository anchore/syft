package options

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCatalogerSelection_PostLoad(t *testing.T) {

	tests := []struct {
		name    string
		options CatalogerSelection
		assert  func(t *testing.T, options CatalogerSelection)
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "mutually exclusive cataloger flags (cat / def-cat)",
			options: CatalogerSelection{
				Catalogers:        []string{"foo,bar", "42"},
				DefaultCatalogers: []string{"some,thing"},
			},
			wantErr: assert.Error,
		},
		{
			name: "mutually exclusive cataloger flags (cat / sel-cat)",
			options: CatalogerSelection{
				Catalogers:       []string{"foo,bar", "42"},
				SelectCatalogers: []string{"some,thing"},
			},
			wantErr: assert.Error,
		},
		{
			name: "allow old cataloger flags",
			options: CatalogerSelection{
				Catalogers: []string{"foo,bar"},
			},
			assert: func(t *testing.T, options CatalogerSelection) {
				assert.Equal(t, []string{"bar", "foo"}, options.DefaultCatalogers) // note: sorted order
				assert.Equal(t, []string{"bar", "foo"}, options.Catalogers)        // note: sorted order
			},
		},
		{
			name: "allow new cataloger flags",
			options: CatalogerSelection{
				SelectCatalogers:  []string{"foo,bar", "42"},
				DefaultCatalogers: []string{"some,thing"},
			},
			assert: func(t *testing.T, options CatalogerSelection) {
				assert.Equal(t, []string{"42", "bar", "foo"}, options.SelectCatalogers) // note: sorted order
				assert.Equal(t, []string{"some", "thing"}, options.DefaultCatalogers)   // note: sorted order
				assert.Empty(t, options.Catalogers)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantErr == nil {
				tt.wantErr = assert.NoError
			}
			tt.wantErr(t, tt.options.PostLoad(), fmt.Sprintf("PostLoad()"))
			if tt.assert != nil {
				tt.assert(t, tt.options)
			}
		})
	}
}
