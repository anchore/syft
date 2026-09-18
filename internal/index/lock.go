package index

import (
	"reflect"
	"sync"
)

// lockable is a read-write lock that hands back its own unlock function.
//
// Returning the unlocker rather than exposing Unlock is what makes the index's lock upgrades safe to
// write: a caller holds an opaque `unlock`, and the node it is walking can tell whether that unlock
// belongs to the write lock or the read lock and upgrade only when it has to. Carried over from the
// prototype this index came from, where the pattern is used throughout.
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
