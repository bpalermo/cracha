// Package listener is the registry of the loopback listeners cracha-agent
// binds inside enrolled pods' network namespaces (docs/design.md, section
// 7.1): identity by socket.
//
// A Registry holds one listener per enrolled pod, bound by a Binder in the
// pod's network namespace, and multiplexes them into one net.Listener for a
// single http.Server. Every connection it accepts is tagged with the pod of
// the listener it arrived on; the server's ConnContext puts that pod in the
// request context, where the handler reads it back with PodFromContext.
// Nothing the client sends carries identity. Closing a pod's entry closes
// its listener and every connection accepted from it: a request in flight
// fails.
package listener

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
)

// Pod identifies an enrolled pod: the Kubernetes object reference the issuer
// is asked for its JWT-SVID with.
type Pod struct {
	Namespace string
	Name      string
	UID       string
}

// String renders the pod for logs.
func (p Pod) String() string {
	return fmt.Sprintf("%s/%s (uid %s)", p.Namespace, p.Name, p.UID)
}

// Entry is one bound listener: the pod and the network namespace path it was
// bound in.
type Entry struct {
	Pod       Pod
	NetnsPath string
}

// Binder binds the agent's listener inside the network namespace at a path.
// netns.Loopback is the real one; tests use a plain loopback listener.
type Binder interface {
	Bind(netnsPath string) (net.Listener, error)
}

// BinderFunc adapts a function to Binder.
type BinderFunc func(netnsPath string) (net.Listener, error)

// Bind implements Binder.
func (f BinderFunc) Bind(netnsPath string) (net.Listener, error) { return f(netnsPath) }

// ErrClosed is returned by Bind once the registry has been closed.
var ErrClosed = errors.New("the listener registry is closed")

// Registry is the set of bound listeners. It implements net.Listener over
// all of them: Accept returns the next connection from any pod's listener.
type Registry struct {
	binder  Binder
	log     *slog.Logger
	onClose func(Pod)

	mu     sync.Mutex
	byUID  map[string]*entry
	closed bool

	conns chan net.Conn
	done  chan struct{}
}

// entry is a bound listener and the connections accepted from it.
type entry struct {
	Entry
	lis   net.Listener
	mu    sync.Mutex
	conns map[*podConn]struct{}
}

// Option configures a Registry.
type Option func(*Registry)

// WithLogger sets the logger.
func WithLogger(log *slog.Logger) Option {
	return func(r *Registry) { r.log = log }
}

// WithCloseHook calls fn whenever a pod's entry is closed, with the pod:
// what else the agent holds for the pod (its token) goes with the listener.
func WithCloseHook(fn func(Pod)) Option {
	return func(r *Registry) { r.onClose = fn }
}

// New returns an empty registry binding with binder.
func New(binder Binder, opts ...Option) *Registry {
	r := &Registry{
		binder: binder,
		log:    slog.Default(),
		byUID:  map[string]*entry{},
		conns:  make(chan net.Conn),
		done:   make(chan struct{}),
	}
	for _, o := range opts {
		o(r)
	}
	return r
}

// Bind binds pod's listener in the network namespace at netnsPath. It is
// idempotent: a pod already bound in that namespace is left as it is. A pod
// bound in another namespace (its sandbox was recreated) is rebound: the old
// listener closes, the new one is bound.
func (r *Registry) Bind(pod Pod, netnsPath string) error {
	if pod.UID == "" {
		return errors.New("the pod has no UID")
	}
	if netnsPath == "" {
		return fmt.Errorf("pod %s has no network namespace path", pod)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ErrClosed
	}
	if old, ok := r.byUID[pod.UID]; ok {
		if old.NetnsPath == netnsPath {
			return nil
		}
		r.log.Info("rebinding the listener: the pod's network namespace changed",
			"pod", pod.String(), "old_netns", old.NetnsPath, "netns", netnsPath)
		delete(r.byUID, pod.UID)
		old.close()
	}
	lis, err := r.binder.Bind(netnsPath)
	if err != nil {
		return fmt.Errorf("binding the listener of %s: %w", pod, err)
	}
	e := &entry{Entry: Entry{Pod: pod, NetnsPath: netnsPath}, lis: lis, conns: map[*podConn]struct{}{}}
	r.byUID[pod.UID] = e
	go r.accept(e)
	r.log.Info("listener bound", "pod", pod.String(), "netns", netnsPath, "addr", lis.Addr().String())
	return nil
}

// Close closes the listener of the pod with uid and reports whether there
// was one.
func (r *Registry) Close(uid string) bool {
	r.mu.Lock()
	e, ok := r.byUID[uid]
	if ok {
		delete(r.byUID, uid)
	}
	r.mu.Unlock()
	if !ok {
		return false
	}
	e.close()
	r.log.Info("listener closed", "pod", e.Pod.String(), "netns", e.NetnsPath)
	if r.onClose != nil {
		r.onClose(e.Pod)
	}
	return true
}

// Lookup returns the entry of the pod with uid.
func (r *Registry) Lookup(uid string) (Entry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.byUID[uid]
	if !ok {
		return Entry{}, false
	}
	return e.Entry, true
}

// Entries returns every bound entry.
func (r *Registry) Entries() []Entry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Entry, 0, len(r.byUID))
	for _, e := range r.byUID {
		out = append(out, e.Entry)
	}
	return out
}

// accept feeds e's connections to Accept until e's listener closes.
func (r *Registry) accept(e *entry) {
	for {
		c, err := e.lis.Accept()
		if err != nil {
			return
		}
		pc := &podConn{Conn: c, pod: e.Pod, entry: e}
		if !e.track(pc) {
			// Closed between the Accept and here: nothing serves it.
			pc.Close()
			return
		}
		select {
		case r.conns <- pc:
		case <-r.done:
			pc.Close()
			return
		}
	}
}

// Accept implements net.Listener: the next connection from any bound
// listener, tagged with its pod.
func (r *Registry) Accept() (net.Conn, error) {
	select {
	case c := <-r.conns:
		return c, nil
	case <-r.done:
		return nil, net.ErrClosed
	}
}

// CloseAll implements net.Listener's Close: every entry is closed and Accept
// returns net.ErrClosed from now on. It is the registry's own close, named
// apart from Close(uid).
func (r *Registry) CloseAll() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	entries := r.byUID
	r.byUID = map[string]*entry{}
	close(r.done)
	r.mu.Unlock()
	for _, e := range entries {
		e.close()
	}
	return nil
}

// Addr implements net.Listener. The listeners have one address each, inside
// their pods; the registry has none of its own.
func (r *Registry) Addr() net.Addr { return addr{} }

// Listener is the registry as the net.Listener an http.Server serves.
func (r *Registry) Listener() net.Listener { return registryListener{r} }

// registryListener adapts the registry to net.Listener, so that the server's
// Close closes everything (CloseAll) without Close(uid) being shadowed.
type registryListener struct{ r *Registry }

func (l registryListener) Accept() (net.Conn, error) { return l.r.Accept() }
func (l registryListener) Close() error              { return l.r.CloseAll() }
func (l registryListener) Addr() net.Addr            { return l.r.Addr() }

type addr struct{}

func (addr) Network() string { return "tcp" }
func (addr) String() string  { return "127.0.0.1 (in each enrolled pod)" }

// ConnContext is for http.Server.ConnContext: the pod of the listener the
// connection arrived on goes into the context of every request on it.
func (r *Registry) ConnContext(ctx context.Context, c net.Conn) context.Context {
	if pc, ok := c.(*podConn); ok {
		return WithPod(ctx, pc.pod)
	}
	return ctx
}

type podKey struct{}

// WithPod returns ctx carrying pod.
func WithPod(ctx context.Context, pod Pod) context.Context {
	return context.WithValue(ctx, podKey{}, pod)
}

// PodFromContext returns the pod a request's connection belongs to.
func PodFromContext(ctx context.Context) (Pod, bool) {
	pod, ok := ctx.Value(podKey{}).(Pod)
	return pod, ok
}

// podConn is an accepted connection and the pod of its listener.
type podConn struct {
	net.Conn
	pod   Pod
	entry *entry
	once  sync.Once
}

// Close closes the connection and forgets it.
func (c *podConn) Close() error {
	var err error
	c.once.Do(func() {
		c.entry.untrack(c)
		err = c.Conn.Close()
	})
	return err
}

// track remembers c, or reports that the entry is closed.
func (e *entry) track(c *podConn) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.conns == nil {
		return false
	}
	e.conns[c] = struct{}{}
	return true
}

func (e *entry) untrack(c *podConn) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.conns, c)
}

// close closes the listener and every connection accepted from it.
func (e *entry) close() {
	_ = e.lis.Close()
	e.mu.Lock()
	conns := e.conns
	e.conns = nil
	e.mu.Unlock()
	for c := range conns {
		_ = c.Close()
	}
}
