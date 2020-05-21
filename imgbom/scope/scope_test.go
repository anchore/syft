package scope

import (
	"testing"

	"github.com/anchore/stereoscope/pkg/image"
	"github.com/anchore/stereoscope/pkg/tree"
)

func testScopeImage(t *testing.T) *image.Image {
	t.Helper()

	one := image.NewLayer(nil)
	one.Tree = tree.NewFileTree()
	one.Tree.AddPath("/tree/first/path.txt")

	two := image.NewLayer(nil)
	two.Tree = tree.NewFileTree()
	two.Tree.AddPath("/tree/second/path.txt")

	i := image.NewImage(nil)
	i.Layers = []image.Layer{one, two}
	err := i.Squash()
	if err != nil {
		t.Fatal("could not squash test image trees")
	}

	return i
}

func TestScope(t *testing.T) {
	refImg := testScopeImage(t)

	cases := []struct {
		name          string
		img           *image.Image
		option        Option
		expectedTrees []*tree.FileTree
		err           bool
	}{
		{
			name:          "AllLayersGoCase",
			option:        AllLayersScope,
			img:           testScopeImage(t),
			expectedTrees: []*tree.FileTree{refImg.Layers[0].Tree, refImg.Layers[1].Tree},
		},
		{
			name:          "SquashedGoCase",
			option:        SquashedScope,
			img:           testScopeImage(t),
			expectedTrees: []*tree.FileTree{refImg.SquashedTree},
		},
		{
			name:   "MissingImage",
			option: SquashedScope,
			err:    true,
		},
		{
			name:   "MissingSquashedTree",
			option: SquashedScope,
			img:    image.NewImage(nil),
			err:    true,
		},
		{
			name:   "NoLayers",
			option: AllLayersScope,
			img:    image.NewImage(nil),
			err:    true,
		},
	}

	for _, c := range cases {
		actual, err := NewScope(c.img, c.option)
		if err == nil && c.err {
			t.Fatal("expected an error but did not find one")
		} else if err != nil && !c.err {
			t.Fatal("expected no error but found one:", err)
		}

		if len(actual.Trees) != len(c.expectedTrees) {
			t.Fatalf("mismatched tree lengths: %d!=%d", len(actual.Trees), len(c.expectedTrees))
		}

		for idx, at := range actual.Trees {
			if !at.Equal(c.expectedTrees[idx]) {
				t.Error("mismatched tree @ idx", idx)
			}
		}
	}

}
