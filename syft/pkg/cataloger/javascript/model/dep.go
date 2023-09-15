package model

import (
	"fmt"
	"sort"
	"strings"
)

// DepGraphNode is a dependency graph node for javascript packages
type DepGraphNode struct {
	Name    string
	Version string
	Path    string
	Develop bool
	// direct dependency (no parents)
	Direct    bool
	Resolved  string
	Integrity string
	// parents
	Parents []*DepGraphNode
	// parents set
	pset map[*DepGraphNode]bool
	// children
	Children []*DepGraphNode
	// children set
	cset   map[*DepGraphNode]bool
	Expand any
}

func (dep *DepGraphNode) AppendChild(child *DepGraphNode) {
	if dep == nil || child == nil {
		return
	}
	if dep.cset == nil {
		dep.cset = map[*DepGraphNode]bool{}
	}
	if child.pset == nil {
		child.pset = map[*DepGraphNode]bool{}
	}
	if !dep.cset[child] {
		dep.Children = append(dep.Children, child)
		dep.cset[child] = true
	}
	if !child.pset[dep] {
		child.Parents = append(child.Parents, dep)
		child.pset[dep] = true
	}
}

func (dep *DepGraphNode) RemoveChild(child *DepGraphNode) {
	for i, c := range dep.Children {
		if c == child {
			dep.Children = append(dep.Children[:i], dep.Children[i+1:]...)
			break
		}
	}
	for i, p := range child.Parents {
		if p == dep {
			child.Parents = append(child.Parents[:i], child.Parents[i+1:]...)
			break
		}
	}
	delete(dep.cset, child)
	delete(child.pset, dep)
}

// ForEach traverses the dependency graph
// deep: true=>depth-first false=>breadth-first
// path: true=>traverse all paths false=>traverse all nodes
// name: true=>iterate child nodes in name order false=>iterate child nodes in add order
// do: operation on the current node, return true to continue iterating child nodes
// do.p: Parent node of the path
// do.n: Child node of the path
func (dep *DepGraphNode) ForEach(deep, path, name bool, do func(p, n *DepGraphNode) bool) {

	if dep == nil {
		return
	}

	var set func(p, n *DepGraphNode) bool
	if path {
		pathSet := map[*DepGraphNode]map[*DepGraphNode]bool{}
		set = func(p, n *DepGraphNode) bool {
			if _, ok := pathSet[p]; !ok {
				pathSet[p] = map[*DepGraphNode]bool{}
			}
			if pathSet[p][n] {
				return true
			}
			pathSet[p][n] = true
			return false
		}
	} else {
		nodeSet := map[*DepGraphNode]bool{}
		set = func(p, n *DepGraphNode) bool {
			if nodeSet[n] {
				return true
			}
			nodeSet[n] = true
			return false
		}
	}

	type pn struct {
		p *DepGraphNode
		n *DepGraphNode
	}

	q := []*pn{{nil, dep}}
	for len(q) > 0 {

		var n *pn
		if deep {
			n = q[len(q)-1]
			q = q[:len(q)-1]
		} else {
			n = q[0]
			q = q[1:]
		}

		if !do(n.p, n.n) {
			continue
		}

		next := make([]*DepGraphNode, len(n.n.Children))
		copy(next, n.n.Children)

		if name {
			sort.Slice(next, func(i, j int) bool { return next[i].Name < next[j].Name })
		}

		if deep {
			for i, j := 0, len(next)-1; i < j; i, j = i+1, j-1 {
				next[i], next[j] = next[j], next[i]
			}
		}

		for _, c := range next {
			if set(n.n, c) {
				continue
			}
			q = append(q, &pn{n.n, c})
		}

	}
}

// ForEachPath traverses the dependency graph path
func (dep *DepGraphNode) ForEachPath(do func(p, n *DepGraphNode) bool) {
	dep.ForEach(false, true, false, do)
}

// ForEachNode traverses the dependency graph nodes
func (dep *DepGraphNode) ForEachNode(do func(p, n *DepGraphNode) bool) {
	dep.ForEach(false, false, false, do)
}

func (dep *DepGraphNode) Index() string {
	return fmt.Sprintf("[%s:%s]", dep.Name, dep.Version)
}

func (dep *DepGraphNode) FlushDevelop() {
	dep.ForEachNode(func(p, n *DepGraphNode) bool {
		n.Develop = n.IsDevelop()
		return true
	})
	dep.ForEachNode(func(p, n *DepGraphNode) bool {
		if !n.Develop {
			for _, p := range n.Parents {
				if p.Develop {
					p.RemoveChild(n)
				}
			}
		}
		return true
	})
}

// IsDeveop determine whether the component is development
// dependency
func (dep *DepGraphNode) IsDevelop() bool {
	if len(dep.Parents) == 0 || dep.Develop {
		return dep.Develop
	}
	for _, p := range dep.Parents {
		if !p.Develop {
			return false
		}
	}
	return true
}

// RemoveDevelop removes development dependency
func (dep *DepGraphNode) RemoveDevelop() {
	dep.ForEachNode(func(p, n *DepGraphNode) bool {
		if n.Develop {
			for _, c := range n.Children {
				n.RemoveChild(c)
			}
			for _, p := range n.Parents {
				p.RemoveChild(n)
			}
			n = nil
			return false
		}
		return true
	})
}

func NewDepGraphNodeMap(key func(...string) string, store func(...string) *DepGraphNode) *DepGraphNodeMap {
	if key == nil {
		key = func(s ...string) string { return strings.Join(s, ":") }
	}
	return &DepGraphNodeMap{key: key, store: store, m: map[string]*DepGraphNode{}}
}

type DepGraphNodeMap struct {
	m     map[string]*DepGraphNode
	key   func(...string) string
	store func(...string) *DepGraphNode
}

func (s *DepGraphNodeMap) Range(do func(k string, v *DepGraphNode) bool) {
	for k, v := range s.m {
		if !do(k, v) {
			break
		}
	}
}

func (s *DepGraphNodeMap) LoadOrStore(words ...string) *DepGraphNode {
	if s == nil || s.key == nil || s.store == nil {
		return nil
	}

	key := s.key(words...)
	dep, ok := s.m[key]
	if !ok {
		dep = s.store(words...)
		s.m[key] = dep
	}
	return dep
}
