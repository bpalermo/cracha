// Package server is the agent's side of cni-mode enrolment (docs/design.md,
// section 7.2): the Unix-socket endpoint the cracha-cni plugin calls on
// every sandbox's ADD and DEL, speaking agent/cni/proto. The plugin is a
// later slice.
//
// On ADD the agent looks the pod up: without the enrolment label it answers
// "not enrolled" and the plugin does nothing; with it, it binds the listener
// in the namespace path it was given, which needs no CRI call. A failed
// lookup or bind fails the ADD (a non-200), and kubelet tears the sandbox
// down and retries: fail closed. On DEL it closes the listener.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/bpalermo/cracha/agent/cni/proto"
	"github.com/bpalermo/cracha/agent/internal/enrol"
	"github.com/bpalermo/cracha/agent/internal/listener"
	"github.com/bpalermo/cracha/agent/internal/serve"
)

// maxBody bounds a request body; the plugin's are a few hundred bytes.
const maxBody = 64 << 10

// Server is the endpoint's http.Handler.
type Server struct {
	enroller *enrol.Enroller
	port     int
	log      *slog.Logger
}

// New returns the endpoint over enroller; port is acknowledged to the
// plugin for an enrolled pod.
func New(enroller *enrol.Enroller, port int, log *slog.Logger) *Server {
	if log == nil {
		log = slog.Default()
	}
	return &Server{enroller: enroller, port: port, log: log}
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case proto.AddPath:
		s.add(w, r)
	case proto.DelPath:
		s.del(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) add(w http.ResponseWriter, r *http.Request) {
	var req proto.AddRequest
	if err := decode(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ref := podOf(req.Pod)
	if ref.Namespace == "" || ref.Name == "" || ref.UID == "" || req.Netns == "" {
		http.Error(w, "the pod's namespace, name and UID and the netns path are required", http.StatusBadRequest)
		return
	}
	log := s.log.With("pod", ref.String(), "netns", req.Netns)
	err := s.enroller.Enrol(r.Context(), ref, req.Netns)
	switch {
	case errors.Is(err, enrol.ErrNotEnrolled):
		log.Debug("ADD: not enrolled")
		answer(w, proto.AddResponse{Enrolled: false})
	case err != nil:
		// The ADD fails; kubelet retries the sandbox.
		log.Warn("ADD refused", "error", err)
		status := http.StatusInternalServerError
		if enrol.Refused(err) {
			status = http.StatusForbidden
		}
		http.Error(w, err.Error(), status)
	default:
		log.Info("ADD: enrolled")
		answer(w, proto.AddResponse{Enrolled: true, Port: s.port})
	}
}

func (s *Server) del(w http.ResponseWriter, r *http.Request) {
	var req proto.DelRequest
	if err := decode(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ref := podOf(req.Pod)
	if ref.UID == "" {
		http.Error(w, "the pod's UID is required", http.StatusBadRequest)
		return
	}
	closed := s.enroller.Unenrol(ref)
	s.log.Info("DEL", "pod", ref.String(), "closed", closed)
	w.WriteHeader(http.StatusOK)
}

func podOf(p proto.PodRef) listener.Pod {
	return listener.Pod{Namespace: p.Namespace, Name: p.Name, UID: p.UID}
}

func decode(r *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBody))
	if err != nil {
		return fmt.Errorf("reading the request: %w", err)
	}
	if err := json.Unmarshal(body, v); err != nil {
		return fmt.Errorf("unreadable request: %w", err)
	}
	return nil
}

func answer(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// Serve runs the endpoint on the Unix socket at path (agent.cni.socket)
// until ctx is done, then removes the socket.
func Serve(ctx context.Context, path string, handler http.Handler, log *slog.Logger) error {
	lis, err := serve.ListenUnix(path)
	if err != nil {
		return err
	}
	defer serve.RemoveSocket(log, path)
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
	}
	return serve.Run(ctx, srv, func() error { return srv.Serve(lis) }, "CNI endpoint "+path, log)
}
