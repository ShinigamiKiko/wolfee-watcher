package auditdelivery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wolfee-watcher/kvisior/internal/auditengine"
	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/pkg/auditrules"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type fixture struct {
	st      *store.Store
	pool    *pgxpool.Pool
	cluster string
	engine  *auditengine.Engine
}

func database(t *testing.T) fixture {
	t.Helper()
	dsn := os.Getenv("AUDIT_TEST_DSN")
	if dsn == "" {
		t.Skip("AUDIT_TEST_DSN must point to disposable migrated PostgreSQL")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	st, err := store.NewFromPool(context.Background(), pool)
	if err != nil {
		t.Fatal(err)
	}
	cluster := fmt.Sprintf("delivery-test-%d", time.Now().UnixNano())
	if err = st.EnsureCluster(context.Background(), cluster); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, table := range []string{"audit_inbox", "audit_ingest_state", "audit_thresholds", "audit_events", "audit_violations", "alerts"} {
			if _, err := pool.Exec(context.Background(), "DELETE FROM "+table+" WHERE cluster_id=$1", cluster); err != nil {
				t.Error(err)
			}
		}
		pool.Exec(context.Background(), "DELETE FROM clusters WHERE id=$1", cluster)
	})
	return fixture{st, pool, cluster, auditengine.New(st, nil)}
}
func rawEvent(id string) json.RawMessage {
	raw, _ := json.Marshal(auditrules.Event{ID: id, Timestamp: time.Now().UTC(), Kind: auditrules.KindCreate, Resource: "configmaps", Namespace: "delivery-tests", Name: id, User: "alice"})
	return raw
}
func (f fixture) request(body string) *http.Request {
	r := httptest.NewRequest("POST", "/internal/push/audit", strings.NewReader(body))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{OrganizationalUnit: []string{"cluster:" + f.cluster}}}}}
	return r
}
func (f fixture) counts(t *testing.T) (int, int, int) {
	t.Helper()
	var events, hits, alerts int
	if err := f.pool.QueryRow(context.Background(), `SELECT (SELECT COUNT(*) FROM audit_events WHERE cluster_id=$1),(SELECT COALESCE(SUM(hits),0) FROM audit_violations WHERE cluster_id=$1),(SELECT COUNT(*) FROM alerts WHERE cluster_id=$1)`, f.cluster).Scan(&events, &hits, &alerts); err != nil {
		t.Fatal(err)
	}
	return events, hits, alerts
}
func TestAckPrecedesRuleProcessingAndRetryIsIdempotent(t *testing.T) {
	f := database(t)
	receiver := NewReceiver(f.st, 1)
	body := `{"events":[` + string(rawEvent("one")) + `]}`
	for i := 0; i < 2; i++ {
		w := httptest.NewRecorder()
		receiver.Events(w, f.request(body))
		if w.Code != 202 {
			t.Fatalf("ACK %d: %s", w.Code, w.Body.String())
		}
	}
	if n, _, _ := f.counts(t); n != 0 {
		t.Fatal("receiver ran rules before ACK")
	}
	status, err := f.st.AuditInboxStatus(context.Background())
	if err != nil || status.Pending != 1 {
		t.Fatalf("inbox: %+v %v", status, err)
	}
	w := httptest.NewRecorder()
	receiver.Events(w, f.request(`{"events":[`+string(rawEvent("two"))+`]}`))
	if w.Code != 503 {
		t.Fatalf("backlog full: %d", w.Code)
	}
	ctx, cancel := context.WithCancel(context.Background())
	worked, err := f.st.ProcessAuditBatch(ctx, func(ctx context.Context, b store.AuditBatch) error {
		if err := Process(ctx, f.engine, b); err != nil {
			return err
		}
		cancel()
		return nil
	})
	if !worked || err == nil {
		t.Fatalf("completion should fail: %v %v", worked, err)
	}
	beforeEvents, beforeHits, beforeAlerts := f.counts(t)
	if beforeEvents != 1 {
		t.Fatalf("event commit lost: %d", beforeEvents)
	}
	restarted := auditengine.New(f.st, nil)
	if _, err = f.st.ProcessAuditBatch(context.Background(), func(ctx context.Context, b store.AuditBatch) error { return Process(ctx, restarted, b) }); err != nil {
		t.Fatal(err)
	}
	events, hits, alerts := f.counts(t)
	if events != beforeEvents || hits != beforeHits || alerts != beforeAlerts {
		t.Fatalf("replay changed effects %d/%d/%d", events, hits, alerts)
	}
	status, err = f.st.AuditInboxStatus(context.Background())
	if err != nil || status.Pending != 0 {
		t.Fatalf("completion %+v %v", status, err)
	}
}
func TestConcurrentWorkersAndFailedBatchRetention(t *testing.T) {
	f := database(t)
	for i := 0; i < 20; i++ {
		if err := f.st.EnqueueAudit(context.Background(), f.cluster, "events", []json.RawMessage{rawEvent(fmt.Sprintf("event-%d", i))}, 100); err != nil {
			t.Fatal(err)
		}
	}
	_, err := f.st.ProcessAuditBatch(context.Background(), func(context.Context, store.AuditBatch) error { return errors.New("temporary failure") })
	if err == nil {
		t.Fatal("failure swallowed")
	}
	if _, err = f.pool.Exec(context.Background(), `UPDATE audit_inbox SET created_at=NOW()-INTERVAL '30 days' WHERE cluster_id=$1`, f.cluster); err != nil {
		t.Fatal(err)
	}
	if _, err = f.st.CleanAuditInbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := f.st.AuditInboxStatus(context.Background())
	if err != nil || status.Pending != 20 || status.MaxAttempts != 1 {
		t.Fatalf("failed batch lost: %+v %v", status, err)
	}
	f.pool.Exec(context.Background(), `UPDATE audit_inbox SET next_attempt_at=NOW() WHERE cluster_id=$1`, f.cluster)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			engine := auditengine.New(f.st, nil)
			for deadline := time.Now().Add(8 * time.Second); time.Now().Before(deadline); {
				_, err := f.st.ProcessAuditBatch(context.Background(), func(ctx context.Context, b store.AuditBatch) error { return Process(ctx, engine, b) })
				if err != nil {
					errs <- err
					return
				}
				status, err := f.st.AuditInboxStatus(context.Background())
				if err != nil {
					errs <- err
					return
				}
				if status.Pending == 0 {
					return
				}
				time.Sleep(time.Millisecond)
			}
			errs <- fmt.Errorf("workers did not drain inbox")
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	if n, _, _ := f.counts(t); n != 20 {
		t.Fatalf("concurrent processing: %d", n)
	}
	status, err = f.st.AuditInboxStatus(context.Background())
	if err != nil || status.Pending != 0 {
		t.Fatalf("pending %+v %v", status, err)
	}
}
func TestUnavailableDatabaseNeverAcknowledges(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://test@127.0.0.1:1/test?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	receiver := NewReceiver(store.FromPool(pool), 100)
	w := httptest.NewRecorder()
	receiver.Events(w, httptest.NewRequest("POST", "/internal/push/audit", strings.NewReader(`{"events":[{"id":"one"}]}`)))
	if w.Code != 503 {
		t.Fatalf("outage ACK %d", w.Code)
	}
	for _, body := range []string{`{"events":[true]}`, `{"events":[{"timestamp":"invalid"}]}`, `{"events":[]} {}`} {
		w = httptest.NewRecorder()
		receiver.Events(w, httptest.NewRequest("POST", "/internal/push/audit", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatalf("bad payload %d: %s", w.Code, body)
		}
	}
}

func TestReceiverReservesCapacityBeforeReadingTheBody(t *testing.T) {
	h := NewReceiver(store.FromPool(nil), 10)
	h.BudgetBytes = 1000
	send := func(length int64) int {
		req := httptest.NewRequest(http.MethodPost, "/internal/push/audit", strings.NewReader("not json"))
		req.ContentLength = length
		w := httptest.NewRecorder()
		h.Events(w, req)
		return w.Code
	}
	if code := send(MaxAuditBody + 1); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized declared body: %d", code)
	}
	if code := send(2000); code != http.StatusServiceUnavailable {
		t.Fatalf("body over the in-flight budget was read: %d", code)
	}
	h.BudgetBytes = 1 << 20
	h.PerCluster = 1
	if !h.acquire(store.DefaultCluster, 10) {
		t.Fatal("slot not granted")
	}
	if code := send(100); code != http.StatusServiceUnavailable {
		t.Fatalf("second concurrent request of the cluster was read: %d", code)
	}
	h.release(store.DefaultCluster, 10)
	if code := send(100); code != http.StatusBadRequest {
		t.Fatalf("admitted request: %d", code)
	}
	if h.reserved != 0 || len(h.active) != 0 || len(h.writes) != 0 {
		t.Fatalf("reservation leaked: reserved=%d active=%v slots=%d", h.reserved, h.active, len(h.writes))
	}
}

func TestInboxSelectionKeepsOrderAndCleanupDrainsBacklog(t *testing.T) {
	f := database(t)
	ctx := context.Background()
	other := f.cluster + "-b"
	if err := f.st.EnsureCluster(ctx, other); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		f.pool.Exec(context.Background(), "DELETE FROM audit_inbox WHERE cluster_id=$1", other)
		f.pool.Exec(context.Background(), "DELETE FROM clusters WHERE id=$1", other)
	})
	if _, err := f.pool.Exec(ctx, `INSERT INTO audit_inbox(cluster_id,kind,batch_key,payload,next_attempt_at) VALUES
	    ($1,'events','a-head','[]',clock_timestamp()+interval '1 hour'),
	    ($1,'events','a-next','[]',clock_timestamp()),
	    ($2,'events','b-head','[]',clock_timestamp())`, f.cluster, other); err != nil {
		t.Fatal(err)
	}
	var seen []string
	collect := func(_ context.Context, b store.AuditBatch) error {
		seen = append(seen, b.Cluster)
		return nil
	}
	for i := 0; i < 3; i++ {
		if _, err := f.st.ProcessAuditBatch(ctx, collect); err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != 1 || seen[0] != other {
		t.Fatalf("processed %v: a delayed head must hold back its own cluster only", seen)
	}
	store.ConfigureAuditRetentionWriter(true)
	defer store.ConfigureAuditRetentionWriter(false)
	if err := f.st.LoadAuditRetention(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `INSERT INTO audit_inbox(cluster_id,kind,batch_key,payload,processed_at)
	    SELECT $1,'log','old-'||n,'[]',clock_timestamp()-$2::interval FROM generate_series(1,12000) n`,
		f.cluster, fmt.Sprintf("%f seconds", (store.AuditRetention()+time.Hour).Seconds())); err != nil {
		t.Fatal(err)
	}
	removed, err := f.st.CleanAuditInbox(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var left int
	if err := f.pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_inbox WHERE cluster_id=$1 AND batch_key LIKE 'old-%'`, f.cluster).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if removed < 12000 || left != 0 {
		t.Fatalf("cleanup removed %d, %d expired rows left", removed, left)
	}
}

func TestNULInARecordIsStoredNotRejected(t *testing.T) {
	f := database(t)
	receiver := NewReceiver(f.st, 10)
	raw, _ := json.Marshal(auditrules.Event{ID: "nul-exec", Timestamp: time.Now().UTC(), Kind: auditrules.KindExec,
		Resource: "pods", Namespace: "delivery-tests", Name: "p", User: "mallory", Commands: []string{"sh", "-c", "id", "x\x00y"}})
	w := httptest.NewRecorder()
	receiver.Events(w, f.request(`{"events":[`+string(raw)+`]}`))
	if w.Code != 202 {
		t.Fatalf("a record with a NUL byte was not accepted: %d %s", w.Code, w.Body.String())
	}
	if _, err := f.st.ProcessAuditBatch(context.Background(), func(ctx context.Context, b store.AuditBatch) error { return Process(ctx, f.engine, b) }); err != nil {
		t.Fatal(err)
	}
	var commands string
	if err := f.pool.QueryRow(context.Background(), `SELECT data->>'commands' FROM audit_events WHERE cluster_id=$1 AND event_uid='nul-exec'`, f.cluster).Scan(&commands); err != nil {
		t.Fatalf("the exec was not stored: %v", err)
	}
	if !strings.Contains(commands, "x�y") {
		t.Fatalf("commands %q", commands)
	}
}

func TestTimedOutBatchRecordsTheAttempt(t *testing.T) {
	f := database(t)
	receiver := NewReceiver(f.st, 10)
	w := httptest.NewRecorder()
	receiver.Events(w, f.request(`{"events":[`+string(rawEvent("slow"))+`]}`))
	if w.Code != 202 {
		t.Fatalf("ACK %d", w.Code)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := f.st.ProcessAuditBatch(ctx, func(ctx context.Context, b store.AuditBatch) error {
		<-ctx.Done()
		return ctx.Err()
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
	var attempts int
	var lastError string
	if err := f.pool.QueryRow(context.Background(), `SELECT attempts, last_error FROM audit_inbox WHERE cluster_id=$1`, f.cluster).Scan(&attempts, &lastError); err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || !strings.Contains(lastError, "deadline") {
		t.Fatalf("a timed-out batch must record its attempt: attempts=%d error=%q", attempts, lastError)
	}
}
