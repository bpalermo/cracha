// Package audit is cracha-access's audit log (docs/design.md, section
// 6.9): one JSON line per request, approval, rejection, write, refusal and
// expiry, and one per relationship change SpiceDB's Watch reports, written
// to stdout for the log pipeline. The log is append-only by construction:
// this package only ever writes a line.
package audit

import (
	"context"
	"io"
	"log/slog"

	"github.com/bpalermo/cracha/access/internal/check"
)

// Kinds of event.
const (
	// EventRequest is a write put up for approval.
	EventRequest = "request"
	// EventApproval and EventRejection decide a pending request.
	EventApproval  = "approval"
	EventRejection = "rejection"
	// EventWrite is a write applied to SpiceDB; EventRefusal one refused.
	EventWrite   = "write"
	EventRefusal = "refusal"
	// EventExpired is a pending request dropped unapproved.
	EventExpired = "expired"
	// EventChange is a relationship change seen on SpiceDB's Watch, by
	// whoever wrote it; EventWatchError a break in that feed.
	EventChange     = "change"
	EventWatchError = "watch_error"
)

// Event is one line of the log. Empty fields are left out.
type Event struct {
	Event string `json:"event"`
	// Operation is grant, revoke, approve or reject.
	Operation string `json:"operation,omitempty"`
	// Caller is the SPIFFE ID the request came over mTLS with; Requester
	// the person or job it named; Reason why.
	Caller    string `json:"caller,omitempty"`
	Requester string `json:"requester,omitempty"`
	Reason    string `json:"reason,omitempty"`
	RequestID string `json:"requestId,omitempty"`
	// RequestedBy is, on an approval or a rejection, the caller who asked.
	RequestedBy  string `json:"requestedBy,omitempty"`
	BreakGlass   bool   `json:"breakGlass,omitempty"`
	Relationship string `json:"relationship,omitempty"`
	// Before and After are the relationship as SpiceDB held it before
	// and after; empty where there was none.
	Before []string `json:"before,omitempty"`
	After  []string `json:"after,omitempty"`
	// PolicyDelta is what the write changes in the composition of every
	// workload it reaches.
	PolicyDelta []check.Delta `json:"policyDelta,omitempty"`
	// Code and Detail say why a write was refused.
	Code          string `json:"code,omitempty"`
	Detail        string `json:"detail,omitempty"`
	BundleVersion string `json:"bundleVersion,omitempty"`
	Token         string `json:"token,omitempty"`
	// Change is, for EventChange, the operation (touch, create, delete),
	// and Metadata the writer's transaction metadata.
	Change   string         `json:"change,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Log writes events.
type Log struct {
	log *slog.Logger
}

// New makes a log that writes JSON lines to w.
func New(w io.Writer) *Log {
	return &Log{log: slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))}
}

// Write logs an event at INFO.
func (l *Log) Write(ctx context.Context, e Event) { l.at(ctx, slog.LevelInfo, e) }

// Warn logs an event at WARN: a break-glass write, a change made outside
// cracha-access, a broken watch.
func (l *Log) Warn(ctx context.Context, e Event) { l.at(ctx, slog.LevelWarn, e) }

func (l *Log) at(ctx context.Context, level slog.Level, e Event) {
	l.log.LogAttrs(ctx, level, "audit", slog.Any("audit", e))
}
