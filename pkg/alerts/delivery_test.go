package alerts

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type fakeWebhookDB struct {
	reserved atomic.Int64
	failures atomic.Int64
}

func (db *fakeWebhookDB) Exec(_ context.Context, sql string, _ ...any) (pgconn.CommandTag, error) {
	switch {
	case strings.Contains(sql, "NOW() + $4::interval"):
		db.reserved.Add(1)
	case strings.Contains(sql, "SET last_error = $3"):
		db.failures.Add(1)
	}
	return pgconn.CommandTag{}, nil
}

func (db *fakeWebhookDB) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("transactions are not used by this test")
}

func webhookQueue(url string, n int) []webhookDelivery {
	queue := make([]webhookDelivery, n)
	for i := range queue {
		queue[i] = webhookDelivery{
			alertID: int64(i + 1),
			kind:    WebhookDiscord,
			config:  WebhookConfig{WebhookURL: url},
			alert:   AlertLog{ID: int64(i + 1), RuleName: "Shell spawned", Severity: "HIGH"},
		}
	}
	return queue
}

func TestDeliverWebhookQueueStopsOnRateLimit(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	db := &fakeWebhookDB{}
	handled, throttled := deliverWebhookQueue(context.Background(), db, srv.Client(), webhookQueue(srv.URL, 5), defaultWebhookMaxAttempts)
	if !throttled || handled != 1 || requests.Load() != 1 {
		t.Fatalf("handled = %d, throttled = %v, requests = %d", handled, throttled, requests.Load())
	}
	if db.reserved.Load() != 1 || db.failures.Load() != 1 {
		t.Fatalf("reserved = %d, failures = %d", db.reserved.Load(), db.failures.Load())
	}
}

func TestDeliverWebhookQueueContinuesAfterOtherErrors(t *testing.T) {
	var requests atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	db := &fakeWebhookDB{}
	handled, throttled := deliverWebhookQueue(context.Background(), db, srv.Client(), webhookQueue(srv.URL, 3), defaultWebhookMaxAttempts)
	if throttled || handled != 3 || requests.Load() != 3 {
		t.Fatalf("handled = %d, throttled = %v, requests = %d", handled, throttled, requests.Load())
	}
}

func TestWebhookStatusErrorKeepsMessage(t *testing.T) {
	err := error(&WebhookStatusError{Kind: WebhookDiscord, StatusCode: 429, Body: "slow down"})
	if err.Error() != "discord webhook: HTTP 429: slow down" {
		t.Fatalf("message = %q", err.Error())
	}
}
