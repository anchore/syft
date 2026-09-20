package index

import (
	"reflect"
	"sync"
)

// lockable is a read-write lock that returns its own unlock function.
//
// Handing back an opaque unlocker (rather than exposing Unlock) lets a node tell whether the caller
// holds the read or write lock and upgrade only when needed. Carried over from the prototype index.
type lockable struct {
	lock sync.RWMutex
}

func (l *lockable) Lock() (unlock func()) {
	l.lock.Lock()
	return l.lock.Unlock
}

func (l *lockable) RLock() (unlock func()) {
	l.lock.RLock()
	return l.lock.RUnlock
}

// isExclusiveLock reports whether the given unlocker is the write lock's rather than the read
// lock's. Compared by function pointer because that is the only handle the caller was given.
func (l *lockable) isExclusiveLock(fn func()) bool {
	return reflect.ValueOf(l.lock.Unlock).Pointer() == reflect.ValueOf(fn).Pointer()
}
