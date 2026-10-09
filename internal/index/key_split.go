// Package index provides a key-split (radix) index, and a forward/reverse pair over it that answers
// prefix and suffix lookups such as "which names end in .jar". It is not safe for concurrent writes: the
// only consumer builds an index once and then only reads it.
package index

import (
	"strings"
)

// ----------------------- KeySplitIndex -----------------------

type KeySplitIndex[T any] struct {
	Node[T]
}

// ----------------------- Node -----------------------

type NodeMap[T any] map[string]*Node[T]

type Node[T any] struct {
	set       bool
	value     T
	keyMap    NodeMap[T]
	keyByChar map[rune]string
}

type NodeUpdateFunc[T any] func(current *Node[T]) (newValue T)

func (n *Node[T]) Value() T {
	return n.value
}

func (n *Node[T]) Get(s string) (out T) {
	v, equal := n._find(s)
	if !equal || v == nil {
		return
	}
	out = v.value
	return
}

func (n *Node[T]) Set(name string, value T) {
	n._makeNodeP(name, nil).SetValue(value)
}

func (n *Node[T]) ByPrefix(s string) []T {
	v, _ := n._find(s)
	if v == nil {
		return nil
	}
	return v.Collect()
}

func (n *Node[T]) Update(name string, f NodeUpdateFunc[T]) {
	node := n._makeNodeP(name, nil)
	node.SetValue(f(node))
}

func (n *Node[T]) SetValue(value T) {
	n.value = value
	n.set = true
}

func (n *Node[T]) Collect() (values []T) {
	n._collect(&values)
	return values
}

func (n *Node[T]) _collect(values *[]T) {
	if n.set {
		*values = append(*values, n.value)
	}

	for _, v := range n.keyMap {
		v._collect(values)
	}
}

// _find returns the node for s and whether it matched exactly.
func (n *Node[T]) _find(s string) (node *Node[T], equal bool) {
	if s == "" {
		return n, true
	}

	ch := rune(s[0])
	key := n.keyByChar[ch]
	if key == "" {
		return nil, false
	}

	offset := len(key)

	// check our part of the key matches
	if offset > 1 {
		for i := 1; i < len(s) && i < offset; i++ {
			if s[i] != key[i] {
				return nil, false
			}
		}
	}

	next := n.keyMap[key]

	// our key matched, it's equal -- just return the node
	if offset == len(s) {
		return next, true
	}

	// our key matched, it's longer -- just return the node as a non-equality match
	if offset >= len(s) {
		return next, false
	}

	// our key matched, but it's shorter -- return what we find for the next portion
	return next._find(s[offset:])
}

// _makeNodeP returns the node for name, creating it (as nodeIfEmpty when given) and splitting existing
// keys on their longest common prefix as needed.
func (n *Node[T]) _makeNodeP(name string, nodeIfEmpty *Node[T]) *Node[T] {
	if name == "" {
		return n
	}

	ch := rune(name[0])
	if n.keyByChar == nil {
		n.keyByChar = map[rune]string{}
		n.keyMap = NodeMap[T]{}
	}

	key, ok := n.keyByChar[ch]
	switch {
	case !ok:
		// no entry for the given character, create one; this is all we have to do
		newNode := orNewNode(nodeIfEmpty)
		n.keyMap[name] = newNode
		n.keyByChar[ch] = name
		return newNode
	case key == name:
		return n.keyMap[key]
	case strings.HasPrefix(key, name):
		// existing key is longer than my key, we can just use the existing and make a new sub-entry for the longer key
		existingNode := n.keyMap[key]
		delete(n.keyMap, key)
		newNode := orNewNode(nodeIfEmpty)
		n.keyMap[name] = newNode
		n.keyByChar[ch] = name
		newNode._makeNodeP(key[len(name):], existingNode)
		return newNode
	case strings.HasPrefix(name, key):
		// existing key is shorter than my key, we can just take the substring to remove the
		// existing string prefix and set the new node as a child of the existing node
		return n.keyMap[key]._makeNodeP(name[len(key):], nodeIfEmpty)
	default:
		// neither the existing key nor my key contains a prefix of the other, so we find
		// the longest common prefix and split BOTH entries as children of a new entry with this common prefix
		commonLength := 1 // the first character already matches
		for commonLength < min(len(key), len(name)) && key[commonLength] == name[commonLength] {
			commonLength++
		}

		existingNode := n.keyMap[key]
		delete(n.keyMap, key)
		newNode := orNewNode(nodeIfEmpty)
		parentNode := &Node[T]{}
		parentNode._makeNodeP(key[commonLength:], existingNode)
		parentNode._makeNodeP(name[commonLength:], newNode)

		common := key[:commonLength]
		n.keyMap[common] = parentNode
		n.keyByChar[ch] = common
		return newNode
	}
}

func orNewNode[T any](n *Node[T]) *Node[T] {
	if n == nil {
		return &Node[T]{}
	}
	return n
}
