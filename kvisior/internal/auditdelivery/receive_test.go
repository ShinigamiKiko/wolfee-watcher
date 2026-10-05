package auditdelivery

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/auditengine"
	"github.com/wolfee-watcher/kvisior/internal/store"
)

func TestBrokenTransferIsRetriedNotRejected(t *testing.T) {
	h := NewReceiver(store.FromPool(nil), 10)
	cases := []struct {
		name string
		body io.Reader
		size int64
		want int
	}{
		{"read timeout mid-body", io.MultiReader(strings.NewReader(`{"events":[{"id":"a"`), iotest.ErrReader(errors.New("i/o timeout"))), -1, http.StatusServiceUnavailable},
		{"connection closed mid-body", strings.NewReader(`{"events":[{"id":"a"`), -1, http.StatusServiceUnavailable},
		{"body over the limit without a length", strings.NewReader(`{"events":["` + strings.Repeat("x", MaxAuditBody) + `"]}`), -1, http.StatusRequestEntityTooLarge},
		{"malformed JSON", strings.NewReader(`{"events":[}`), -1, http.StatusBadRequest},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/internal/push/audit", c.body)
		r.ContentLength = c.size
		w := httptest.NewRecorder()
		h.Events(w, r)
		if w.Code != c.want {
			t.Errorf("%s: %d, want %d", c.name, w.Code, c.want)
		}
	}
}

type countingProcessor struct {
	events, records int
}

func (p *countingProcessor) IngestEvents(_ context.Context, _ string, raws []json.RawMessage) error {
	p.events += len(raws)
	return nil
}

func (p *countingProcessor) IngestLog(_ context.Context, _ string, records []auditengine.LogRecord) error {
	p.records += len(records)
	return nil
}

func TestOneUnreadableRecordDoesNotBlockTheCluster(t *testing.T) {
	p := &countingProcessor{}
	good := json.RawMessage(`{"id":"good","kind":"create"}`)
	bad := json.RawMessage(`{"id":"bad","timestamp":"not a time"}`)
	batch := store.AuditBatch{ID: 1, Cluster: "c1", Kind: "events", Payload: []json.RawMessage{bad, good}, CreatedAt: time.Now()}
	if err := Process(context.Background(), p, batch); err != nil || p.events != 1 {
		t.Fatalf("events: err=%v processed=%d", err, p.events)
	}
	batch.Kind, batch.Payload = "log", []json.RawMessage{json.RawMessage(`{"event":{"timestamp":"not a time"}}`), json.RawMessage(`{"event":{"id":"ok"}}`)}
	if err := Process(context.Background(), p, batch); err != nil || p.records != 1 {
		t.Fatalf("log: err=%v processed=%d", err, p.records)
	}
}
