package service

import (
	"context"
	"time"

	"github.com/bpalermo/cracha/access/internal/audit"
	"github.com/bpalermo/cracha/access/internal/store"
)

// Writer is the transaction metadata's writer on every write this service
// makes.
const Writer = "cracha-access"

// WatchAudit logs every relationship change SpiceDB's Watch reports for
// the types cracha-access writes and checks against, until ctx ends: a
// change cracha-access made carries its transaction metadata (who, why);
// one without it was made by something else, around the service, and is
// logged at WARN, so that no write goes unseen (design 6.9). It follows
// the feed from when it starts.
func WatchAudit(ctx context.Context, st *store.Store, log *audit.Log, backoff time.Duration) {
	_ = st.Watch(ctx, store.WatchTypes, "", backoff, func(c store.Change) {
		if c.Operation == "watch_error" {
			log.Warn(ctx, audit.Event{Event: audit.EventWatchError, Token: c.Token, Metadata: c.Metadata})
			return
		}
		ev := audit.Event{Event: audit.EventChange, Change: c.Operation, Relationship: c.Relationship.String(), Token: c.Token, Metadata: c.Metadata}
		if c.Metadata["writer"] != Writer {
			ev.Detail = "written outside cracha-access"
			log.Warn(ctx, ev)
			return
		}
		ev.Caller, _ = c.Metadata["caller"].(string)
		log.Write(ctx, ev)
	})
}
