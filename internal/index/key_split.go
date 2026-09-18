// Package index provides a concurrent key-split (radix) index and a forward/reverse pair over it.
//
// Ported from a prototype dir scan package whose search strategy this
// exists to serve: a path index that answers "which entries end in .jar" and "which entries live
// under this directory" without walking a tree, so a cataloger's `**/*.ext` glob is a lookup keyed
// on the extension rather than a scan of every path.
//
// Kept close to the original so the two can be diffed. The lock type is local (see lock.go) rather
// than pulled in from the prototype's sync/atomic package, which carries unrelated helpers.
package index

import (
	"bytes"
	"encoding/json"
	"strings"
)

// ----------------------- KeySplitIndex -----------------------

type KeySplitIndex[T any] struct {
	Node[T]
}

var _ interface {
	json.Marshaler
	json.Unmarshaler
} = (*KeySplitIndex[int])(nil)

func (n *KeySplitIndex[T]) MarshalJSON() ([]byte, error) {
	values := map[string]T{}
	collectValues(values, "", &n.Node)
	buf := &bytes.Buffer{}
	enc := json.NewEncoder(buf)
	enc.SetEscapeHTML(false)
	err := enc.Encode(values)
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (n *KeySplitIndex[T]) UnmarshalJSON(bytes []byte) error {
	values := map[string]T{}
	err := json.Unmarshal(bytes, &values)
	if err != nil {
		return err
	}
	for k, v := range values {
		n.Set(k, v)
	}
	return nil
}

func collectValues[T any](values map[string]T, key string, node *Node[T]) {
	if node.set {
		values[key] = node.value
	}
	for segment, child := range node.keyMap {
		collectValues(values, key+segment, child)
	}
}

// ----------------------- Node -----------------------

type NodeMap[T any] map[string]*Node[T]

type Node[T any] struct {
	lockable
	set       bool
	value     T
	keyMap    NodeMap[T]
	keyByChar map[rune]string
}

type NodeUpdateFunc[T any] func(current *Node[T]) (newValue T)

func (n *Node[T]) Value() (v T) {
	unlock := n.RLock()
	v = n.value
	unlock()
	return
}

func (n *Node[T]) Contains(s string) bool {
	_, equal := n._find(s)
	return equal
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
	node := n._makeNodeP(nil, name, nil)
	node.SetValue(value)
}

func (n *Node[T]) ByPrefix(s string) []T {
	v, _ := n._find(s)
	if v == nil {
		return nil
	}
	return v.Collect()
}

func (n *Node[T]) Update(name string, f NodeUpdateFunc[T]) {
	unlock := n.Lock()
	node := n._makeNodeP(&unlock, name, nil)
	v := f(node)
	node.SetValue(v)
	unlock()
}

func (n *Node[T]) SetValue(value T) {
	unlock := n.Lock()
	n.value = value
	n.set = true
	unlock()
}

func (n *Node[T]) UnsetValue() {
	unlock := n.Lock()
	var zero T
	n.value = zero
	n.set = false
	unlock()
}

func (n *Node[T]) Collect() (values []T) {
	n._collect(&values)
	return values
}

func (n *Node[T]) _collect(values *[]T) {
	unlock := n.RLock()
	if n.set {
		*values = append(*values, n.value)
	}

	for _, v := range n.keyMap {
		v._collect(values)
	}

	unlock()
}

// _startsWith returns the node starting with the given string
func (n *Node[T]) _find(s string) (node *Node[T], equal bool) {
	defer n.RLock()()

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

//nolint:funlen,gocognit
func (n *Node[T]) _makeNodeP(unlock *func(), name string, nodeIfEmpty *Node[T]) *Node[T] {
	if name == "" {
		return n
	}

	if unlock == nil {
		rUnlock := n.RLock()
		n = n._makeNodeP(&rUnlock, name, nodeIfEmpty)
		rUnlock()
		return n
	}

	ch := rune(name[0])

	if n.keyByChar == nil || n.keyMap == nil {
		n._exclusiveLock(unlock)

		if n.keyByChar == nil {
			n.keyByChar = map[rune]string{}
		}
		if n.keyMap == nil {
			n.keyMap = NodeMap[T]{}
		}
	}

	key, ok := n.keyByChar[ch]

	// no entry for the given character
	if !ok {
		// check again with an exclusive lock before creating a new entry
		n._exclusiveLock(unlock)

		key, ok = n.keyByChar[ch]
		if !ok {
			// no entry for the given character, create one; this is all we have to do
			newNode := nodeIfEmpty
			if newNode == nil {
				newNode = &Node[T]{}
			}
			n.keyMap[name] = newNode
			n.keyByChar[ch] = name

			return newNode
		}
	}

	switch {
	case key == name:
		existingNode := n.keyMap[key]
		if existingNode == nil {
			// try this again, something changed between read checks and exclusive lock
			return n._makeNodeP(unlock, name, nodeIfEmpty)
		}

		return existingNode
	case strings.HasPrefix(key, name):
		// existing key is longer than my key, we can just use the existing and make a new sub-entry for the longer key
		n._exclusiveLock(unlock)

		existingNode := n.keyMap[key]
		if existingNode == nil {
			// try this again, something changed between read checks and exclusive lock
			return n._makeNodeP(unlock, name, nodeIfEmpty)
		}
		delete(n.keyMap, key)

		newNode := nodeIfEmpty
		if newNode == nil {
			newNode = &Node[T]{}
		}
		n.keyMap[name] = newNode
		n.keyByChar[ch] = name

		next := key[len(name):]
		_ = newNode._makeNodeP(nil, next, existingNode)

		return newNode
	case strings.HasPrefix(name, key):
		// existing key is shorter than my key, we can just take the substring to remove the
		// existing string prefix and set the new node as a child of the existing node
		n._exclusiveLock(unlock)

		existingNode := n.keyMap[key]
		if existingNode == nil {
			// try this again, something changed between read checks and exclusive lock
			return n._makeNodeP(unlock, name, nodeIfEmpty)
		}

		next := name[len(key):]
		return existingNode._makeNodeP(nil, next, nodeIfEmpty)
	default:
		// neither the existing key nor my key contains a prefix of the other, so we find
		// the longest common prefix and split BOTH entries as children of a new entry with this common prefix
		n._exclusiveLock(unlock)

		commonLength := 1 // the first character already matches
		minLength := len(key)
		if len(name) < minLength {
			minLength = len(name)
		}
		for ; commonLength < minLength; commonLength++ {
			if key[commonLength] != name[commonLength] {
				break
			}
		}

		existingNode := n.keyMap[key]
		if existingNode == nil {
			// try this again, something changed between read checks and exclusive lock
			return n._makeNodeP(unlock, name, nodeIfEmpty)
		}
		delete(n.keyMap, key)

		newNode := nodeIfEmpty
		if newNode == nil {
			newNode = &Node[T]{}
		}
		parentNode := &Node[T]{}
		parentNode._makeNodeP(nil, key[commonLength:], existingNode)
		parentNode._makeNodeP(nil, name[commonLength:], newNode)

		common := key[:commonLength]
		n.keyMap[common] = parentNode
		n.keyByChar[ch] = common

		return newNode
	}
}

func (n *Node[T]) _exclusiveLock(unlocker *func()) {
	if !n.isExclusiveLock(*unlocker) {
		(*unlocker)()
		*unlocker = n.Lock()
	}
}
