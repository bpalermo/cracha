package driver

import (
	"crypto/sha256"
	"sync"
	"time"

	"github.com/bpalermo/cracha/csi/internal/token"
)

// Entry is a published volume: the pod it belongs to, where its token is and
// how fresh it is.
type Entry struct {
	VolumeID       string
	PodUID         string
	Namespace      string
	Name           string
	ServiceAccount string
	TargetPath     string

	// TokenIssued and TokenExpiry bound the token on disk; rotation replaces
	// it once less than half of that span remains.
	TokenIssued time.Time
	TokenExpiry time.Time
	// TokenOwner is the owner the token on disk was written for: the pod's
	// fsGroup, or the plugin's default.
	TokenOwner token.Owner

	// reviewed is the hash of the kubelet-supplied service account token that
	// last passed the context check, and reviewExpiry when kubelet says that
	// token expires. The same token gets the same verdict, so a republish only
	// asks the API server again when kubelet rotated the token.
	reviewed     [sha256.Size]byte
	reviewExpiry time.Time
}

// fresh reports whether at least half of the token's lifetime remains at now.
func (e *Entry) fresh(now time.Time) bool {
	lifetime := e.TokenExpiry.Sub(e.TokenIssued)
	remaining := e.TokenExpiry.Sub(now)
	return lifetime > 0 && remaining > 0 && 2*remaining >= lifetime
}

// serves reports whether the token on disk still serves a republish at now
// that asks for owner: it is fresh, it is there, and it was written for that
// owner. The owner cannot change for one pod, since the fsGroup is part of
// the pod spec, but a republish that asks for another one gets it.
func (e *Entry) serves(now time.Time, owner token.Owner) bool {
	return e.fresh(now) && e.TokenOwner == owner && tokenExists(e.TargetPath)
}

// Registry is the in-memory set of published volumes, keyed by volume ID. It
// is rebuilt by kubelet's republishes after a restart (design, section 8).
type Registry struct {
	mu      sync.Mutex
	entries map[string]*Entry
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]*Entry{}}
}

// Get returns a copy of the entry for volumeID.
func (r *Registry) Get(volumeID string) (Entry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[volumeID]
	if !ok {
		return Entry{}, false
	}
	return *e, true
}

// Put stores e under its volume ID.
func (r *Registry) Put(e Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries[e.VolumeID] = &e
}

// Delete drops the entry for volumeID, if any.
func (r *Registry) Delete(volumeID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, volumeID)
}

// Len is the number of published volumes.
func (r *Registry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.entries)
}

// keyedMutex serialises the operations on one volume while leaving different
// volumes independent: a publish holds its lock through the issuer fetch and
// its retries, which must not stall every other pod on the node.
type keyedMutex struct {
	mu    sync.Mutex
	locks map[string]*keyedLock
}

type keyedLock struct {
	sync.Mutex
	refs int
}

func newKeyedMutex() *keyedMutex {
	return &keyedMutex{locks: map[string]*keyedLock{}}
}

// Lock locks key and returns the matching unlock.
func (k *keyedMutex) Lock(key string) func() {
	k.mu.Lock()
	l, ok := k.locks[key]
	if !ok {
		l = &keyedLock{}
		k.locks[key] = l
	}
	l.refs++
	k.mu.Unlock()

	l.Lock()
	return func() {
		l.Unlock()
		k.mu.Lock()
		l.refs--
		if l.refs == 0 {
			delete(k.locks, key)
		}
		k.mu.Unlock()
	}
}
