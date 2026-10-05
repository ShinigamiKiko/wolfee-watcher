package auditengine

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/pkg/auditrules"
)

func TestUnstorableBytesDoNotStallTheBatch(t *testing.T) {
	f := database(t)
	e := f.engine()
	e.hub = nil
	yes := true
	bad := event("nul-log")
	bad.Kind = auditrules.KindGet
	bad.Name = "x\x00y"
	bad.Allowed = &yes
	good := event("good-log")
	good.Kind = auditrules.KindGet
	good.Allowed = &yes
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{{Event: bad}, {Event: good}}); err != nil {
		t.Fatalf("a NUL byte in a record failed the batch: %v", err)
	}
	exec := event("nul-exec")
	exec.Kind = auditrules.KindExec
	exec.Commands = []string{"sh", "-c", "a\x00b"}
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{rawEvent(exec), rawEvent(event("after"))}); err != nil {
		t.Fatalf("a NUL byte in an exec argument failed the batch: %v", err)
	}
	f.counts(t, 4, 0, 0)
	var name string
	if err := f.pool.QueryRow(f.ctx, `SELECT name FROM audit_events WHERE cluster_id=$1 AND data->>'auditID'='nul-log'`, f.cluster).Scan(&name); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(name, 0) || !strings.HasPrefix(name, "x") {
		t.Fatalf("stored name %q", name)
	}
}

func TestOldEventIsEnrichedByItsOwnTimestamp(t *testing.T) {
	f := database(t)
	r := eachRule()
	r.Spec.IPMode = auditrules.IPIn
	r.Spec.IPList = "10.20.0.0/16"
	e := f.engine(r)
	e.hub = nil
	at := time.Now().UTC().Add(-5 * time.Hour)
	adm := event("replayed")
	adm.Timestamp = at
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{rawEvent(adm)}); err != nil {
		t.Fatal(err)
	}
	final := event("replayed-log")
	final.Timestamp = at.Add(2 * time.Second)
	final.SourceIPs = []string{"10.20.14.36"}
	yes := true
	final.Allowed = &yes
	final.StatusCode = 201
	rec := LogRecord{EventUID: "replayed", Event: final}
	for i := 0; i < 2; i++ {
		if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{rec}); err != nil {
			t.Fatal(err)
		}
	}
	f.counts(t, 1, 1, 1)
	var origin string
	if err := f.pool.QueryRow(f.ctx, `SELECT origin FROM audit_events WHERE cluster_id=$1`, f.cluster).Scan(&origin); err != nil {
		t.Fatal(err)
	}
	if origin != "both" {
		t.Fatalf("an event replayed from an old log was not enriched: origin=%s", origin)
	}
}

func (f *fixture) actor(t *testing.T) (user, origin, actedAs string, events int) {
	t.Helper()
	if err := f.pool.QueryRow(f.ctx,
		`SELECT COALESCE(MAX("user"), ''), COALESCE(MAX(origin), ''), COALESCE(MAX(data->>'impersonatedUser'), ''), COUNT(*)
		   FROM audit_events WHERE cluster_id=$1`, f.cluster).Scan(&user, &origin, &actedAs, &events); err != nil {
		t.Fatal(err)
	}
	return
}

func TestImpersonationIsAttributedToTheRealUser(t *testing.T) {
	f := database(t)
	people := eachRule()
	people.ID, people.Alert = "people-delete", false
	people.Spec.Kinds = []string{auditrules.KindDelete}
	people.Spec.Subject = auditrules.SubjectPeople
	e := f.engine(people)
	e.hub = nil
	alias := "system:serviceaccount:kube-system:generic-garbage-collector"
	adm := event("impersonated")
	adm.Kind, adm.Resource, adm.Name, adm.User = auditrules.KindDelete, "secrets", "db", alias
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{rawEvent(adm)}); err != nil {
		t.Fatal(err)
	}
	f.counts(t, 1, 0, 0)
	final := adm
	final.ID, final.User, final.ImpersonatedUser = "audit-imp", "m.ivanova", alias
	final.Groups = []string{"dev", "system:authenticated"}
	final.ImpersonatedGroups = []string{"system:masters"}
	final.SourceIPs = []string{"203.0.113.48"}
	yes := true
	final.Allowed, final.StatusCode = &yes, 200
	for i := 0; i < 2; i++ {
		if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{{EventUID: "impersonated", Event: final}}); err != nil {
			t.Fatal(err)
		}
	}
	user, origin, actedAs, events := f.actor(t)
	if user != "m.ivanova" || actedAs != alias || origin != "both" || events != 1 {
		t.Fatalf("user=%q actedAs=%q origin=%q events=%d", user, actedAs, origin, events)
	}
	f.counts(t, 1, 1, 0)
	var actor, groups, actedGroups string
	if err := f.pool.QueryRow(f.ctx, `SELECT actor FROM audit_violations WHERE cluster_id=$1`, f.cluster).Scan(&actor); err != nil {
		t.Fatal(err)
	}
	if actor != "m.ivanova" {
		t.Fatalf("a rule for people must fire on the real user, got actor %q", actor)
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT data->>'groups', data->>'impersonatedGroups' FROM audit_events WHERE cluster_id=$1`, f.cluster).Scan(&groups, &actedGroups); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(groups, "dev") || !strings.Contains(actedGroups, "system:masters") {
		t.Fatalf("groups=%s impersonatedGroups=%s", groups, actedGroups)
	}
}

func webhookChange(id, user string) auditrules.Event {
	ev := event(id)
	ev.Kind, ev.Resource, ev.Namespace, ev.Name, ev.User = auditrules.KindUpdate, "validatingwebhookconfigurations", "", "kyverno", user
	return ev
}

func TestWebhookChangeGetsItsUserFromTheLog(t *testing.T) {
	at := time.Now().UTC()
	rule := eachRule()
	rule.ID = "vwh-update"
	rule.Spec.Kinds = []string{auditrules.KindUpdate}
	rule.Spec.Resources = []string{"validatingwebhookconfigurations"}
	yes := true
	logRecord := func() LogRecord {
		ev := webhookChange("audit-vwh", "m.ivanova")
		ev.Timestamp = at
		ev.AuditID, ev.SourceIPs, ev.Allowed, ev.StatusCode = "audit-vwh", []string{"10.20.14.36"}, &yes, 200
		return LogRecord{Event: ev}
	}
	informer := func() json.RawMessage {
		ev := webhookChange("informer-vwh-update-1", "unknown")
		ev.Timestamp = at
		ev.Source, ev.ServiceAccount = "kubernetes-informer", "unknown"
		return rawEvent(ev)
	}
	for _, logFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("logFirst=%v", logFirst), func(t *testing.T) {
			f := database(t)
			e := f.engine(rule)
			e.hub = nil
			steps := []func() error{
				func() error { return e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{informer()}) },
				func() error { return e.IngestLog(f.ctx, f.cluster, []LogRecord{logRecord()}) },
			}
			if logFirst {
				steps[0], steps[1] = steps[1], steps[0]
			}
			for round := 0; round < 2; round++ {
				for _, step := range steps {
					if err := step(); err != nil {
						t.Fatal(err)
					}
				}
			}
			user, _, _, events := f.actor(t)
			if events != 1 || user != "m.ivanova" {
				t.Fatalf("one change must be one event with the real user: events=%d user=%q", events, user)
			}
			f.counts(t, 1, 1, 1)
			var actor, ip string
			if err := f.pool.QueryRow(f.ctx, `SELECT actor, source_ip FROM audit_violations WHERE cluster_id=$1`, f.cluster).Scan(&actor, &ip); err != nil {
				t.Fatal(err)
			}
			if actor != "m.ivanova" || ip != "10.20.14.36" {
				t.Fatalf("violation actor=%q ip=%q", actor, ip)
			}
			alerts, _, err := f.st.Cluster(f.cluster).QueryAlerts(f.ctx, 0, 10)
			if err != nil || len(alerts) != 1 {
				t.Fatalf("alerts=%d err=%v", len(alerts), err)
			}
			if a := alerts[0]; a.User != "m.ivanova" || !strings.HasPrefix(a.Action, "update validatingwebhookconfigurations/kyverno") {
				t.Fatalf("the alert must name the user once the log arrives: user=%q action=%q detail=%q", a.User, a.Action, a.Detail)
			}
		})
	}
}

func TestDeniedAttemptDoesNotClaimSomeoneElsesChange(t *testing.T) {
	f := database(t)
	e := f.engine()
	e.hub = nil
	seen := webhookChange("informer-vwh-update-2", "unknown")
	seen.Source = "kubernetes-informer"
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{rawEvent(seen)}); err != nil {
		t.Fatal(err)
	}
	no, yes := false, true
	denied := webhookChange("audit-denied", "d.orlov")
	denied.AuditID, denied.Allowed, denied.StatusCode = "audit-denied", &no, 403
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{{Event: denied}}); err != nil {
		t.Fatal(err)
	}
	var user string
	if err := f.pool.QueryRow(f.ctx, `SELECT "user" FROM audit_events WHERE cluster_id=$1 AND event_uid='informer-vwh-update-2'`, f.cluster).Scan(&user); err != nil {
		t.Fatal(err)
	}
	if user != "unknown" {
		t.Fatalf("a denied attempt was recorded as the author of the change: %q", user)
	}
	f.counts(t, 2, 0, 0)
	done := webhookChange("audit-done", "m.ivanova")
	done.AuditID, done.Allowed, done.StatusCode = "audit-done", &yes, 200
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{{Event: done}}); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT "user" FROM audit_events WHERE cluster_id=$1 AND event_uid='informer-vwh-update-2'`, f.cluster).Scan(&user); err != nil {
		t.Fatal(err)
	}
	if user != "m.ivanova" {
		t.Fatalf("the change kept user %q", user)
	}
	f.counts(t, 2, 0, 0)
}

func TestRapidChangesKeepTheirOwnAuthors(t *testing.T) {
	f := database(t)
	e := f.engine()
	e.hub = nil
	yes := true
	at := time.Now().UTC()
	watch := func(rv, prev string) json.RawMessage {
		ev := webhookChange("informer-vwh-update-uid-1-"+rv, "unknown")
		ev.Timestamp, ev.Source, ev.UID, ev.ResourceVersion, ev.PrevResourceVersion = at, "kubernetes-informer", "uid-1", rv, prev
		return rawEvent(ev)
	}
	logged := func(id, user, prev string) LogRecord {
		ev := webhookChange(id, user)
		ev.Timestamp, ev.AuditID, ev.UID, ev.PrevResourceVersion, ev.Allowed, ev.StatusCode = at, id, "uid-1", prev, &yes, 200
		return LogRecord{Event: ev}
	}
	author := func(rv string) string {
		t.Helper()
		var user string
		if err := f.pool.QueryRow(f.ctx,
			`SELECT "user" FROM audit_events WHERE cluster_id=$1 AND origin='both' AND data->>'resourceVersion'=$2`,
			f.cluster, rv).Scan(&user); err != nil {
			t.Fatalf("change %s: %v", rv, err)
		}
		return user
	}
	steps := []func() error{
		func() error {
			return e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{watch("11", "10"), watch("12", "11")})
		},
		func() error { return e.IngestLog(f.ctx, f.cluster, []LogRecord{logged("audit-b", "b.second", "11")}) },
		func() error { return e.IngestLog(f.ctx, f.cluster, []LogRecord{logged("audit-a", "a.first", "10")}) },
		func() error {
			return e.IngestLog(f.ctx, f.cluster, []LogRecord{logged("audit-d", "d.fourth", "13"), logged("audit-c", "c.third", "12")})
		},
		func() error {
			return e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{watch("13", "12"), watch("14", "13")})
		},
		func() error { return e.IngestLog(f.ctx, f.cluster, []LogRecord{logged("audit-noop", "e.noop", "14")}) },
	}
	for i, step := range steps {
		if err := step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	for rv, want := range map[string]string{"11": "a.first", "12": "b.second", "13": "c.third", "14": "d.fourth"} {
		if got := author(rv); got != want {
			t.Errorf("change %s is attributed to %q, want %q", rv, got, want)
		}
	}
	f.counts(t, 5, 0, 0)
}

func TestConflictingWritesAndEmptyRequestsKeepTheirAuthors(t *testing.T) {
	f := database(t)
	e := f.engine()
	e.hub = nil
	yes := true
	at := time.Now().UTC()
	watch := func(rv, prev string) json.RawMessage {
		ev := webhookChange("informer-vwh-update-uid-1-"+rv, "unknown")
		ev.Timestamp, ev.Source, ev.UID, ev.ResourceVersion, ev.PrevResourceVersion = at, "kubernetes-informer", "uid-1", rv, prev
		return rawEvent(ev)
	}
	logged := func(user, firstSeen string, finished int, unchanged bool) LogRecord {
		ev := webhookChange("audit-"+user, user)
		done := at.Add(time.Duration(finished) * time.Millisecond)
		ev.Timestamp, ev.AuditID, ev.UID, ev.PrevResourceVersion, ev.Allowed, ev.StatusCode = at, ev.ID, "uid-1", firstSeen, &yes, 200
		ev.CompletedAt, ev.Unchanged = &done, unchanged
		return LogRecord{Event: ev}
	}
	events := func(raws ...json.RawMessage) func() error {
		return func() error { return e.IngestEvents(f.ctx, f.cluster, raws) }
	}
	records := func(recs ...LogRecord) func() error {
		return func() error { return e.IngestLog(f.ctx, f.cluster, recs) }
	}
	steps := []func() error{
		events(watch("21", "20"), watch("22", "21")),
		records(logged("won", "20", 1, false), logged("retried", "20", 3, false)),

		records(logged("retried-early", "30", 4, false), logged("won-early", "30", 2, false)),
		events(watch("31", "30"), watch("32", "31")),

		records(logged("empty", "40", 1, true)),
		events(watch("41", "40")),
		records(logged("real", "40", 5, false)),

		records(logged("empty-after", "41", 6, true)),
	}
	for i, step := range steps {
		if err := step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	want := map[string]string{"21": "won", "22": "retried", "31": "won-early", "32": "retried-early", "41": "real"}
	for rv, user := range want {
		var got string
		if err := f.pool.QueryRow(f.ctx,
			`SELECT "user" FROM audit_events WHERE cluster_id=$1 AND origin='both' AND data->>'resourceVersion'=$2`,
			f.cluster, rv).Scan(&got); err != nil {
			t.Fatalf("change %s: %v", rv, err)
		}
		if got != user {
			t.Errorf("change %s is attributed to %q, want %q", rv, got, user)
		}
	}
	var alone int
	if err := f.pool.QueryRow(f.ctx,
		`SELECT COUNT(*) FROM audit_events WHERE cluster_id=$1 AND origin='apilog' AND "user" LIKE 'empty%' AND data->>'unchanged'='true'`,
		f.cluster).Scan(&alone); err != nil {
		t.Fatal(err)
	}
	if alone != 2 {
		t.Errorf("%d of 2 requests that changed nothing are stored on their own", alone)
	}
	f.counts(t, 7, 0, 0)
}

func TestSourceIPRuleUsesTheAddressTheAPIServerSaw(t *testing.T) {
	f := database(t)
	t.Cleanup(func() {
		if _, err := f.pool.Exec(f.ctx, "DELETE FROM audit_trusted_proxies WHERE cluster_id=$1", f.cluster); err != nil {
			t.Error(err)
		}
	})
	outside := eachRule()
	outside.ID, outside.Alert = "outside-office", false
	outside.Spec.Kinds = []string{auditrules.KindDelete}
	outside.Spec.IPMode, outside.Spec.IPList = auditrules.IPNotIn, "10.20.0.0/16"
	yes := true
	request := func(id string) auditrules.Event {
		ev := event(id)
		ev.Kind, ev.Resource, ev.Name, ev.User = auditrules.KindDelete, "secrets", "db-"+id, "d.orlov"
		ev.AuditID, ev.Allowed, ev.StatusCode = id, &yes, 200
		ev.SourceIPs = []string{"10.20.14.36", "203.0.113.9"}
		ev.ClientIP = "10.20.14.36"
		return ev
	}
	address := func(uid string) (column, client string) {
		t.Helper()
		if err := f.pool.QueryRow(f.ctx,
			`SELECT COALESCE(source_ip, ''), COALESCE(data->>'clientIP', '') FROM audit_events WHERE cluster_id=$1 AND (event_uid=$2 OR data->>'auditID'=$2)`,
			f.cluster, uid).Scan(&column, &client); err != nil {
			t.Fatalf("%s: %v", uid, err)
		}
		return
	}
	e := f.engine(outside)
	e.hub = nil
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{{Event: request("forged")}}); err != nil {
		t.Fatal(err)
	}
	admitted := request("admitted")
	admitted.SourceIPs, admitted.ClientIP, admitted.Allowed, admitted.StatusCode = nil, "", nil, 0
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{rawEvent(admitted)}); err != nil {
		t.Fatal(err)
	}
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{{EventUID: "admitted", Event: request("admitted-log")}}); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{"forged", "admitted"} {
		if column, client := address(uid); column != "203.0.113.9" || client != "203.0.113.9" {
			t.Errorf("%s: a forwarded address was taken for the source: column=%q clientIP=%q", uid, column, client)
		}
	}
	f.counts(t, 2, 2, 0)

	if err := f.st.Cluster(f.cluster).SaveAuditTrustedProxies(f.ctx, store.AuditProxySettings{
		Proxies: "203.0.113.9", HeadersSanitized: true,
	}, "test"); err != nil {
		t.Fatal(err)
	}
	behind := f.engine(outside)
	behind.hub = nil
	if err := behind.IngestLog(f.ctx, f.cluster, []LogRecord{{Event: request("via-proxy")}}); err != nil {
		t.Fatal(err)
	}
	if column, client := address("via-proxy"); column != "10.20.14.36" || client != "10.20.14.36" {
		t.Errorf("behind a trusted proxy the address it reports is the source: column=%q clientIP=%q", column, client)
	}
	f.counts(t, 3, 2, 0)
}

func changeAuthors(t *testing.T, f *fixture, want map[string]string) {
	t.Helper()
	for rv, user := range want {
		var got string
		if err := f.pool.QueryRow(f.ctx,
			`SELECT "user" FROM audit_events WHERE cluster_id=$1 AND origin='both' AND data->>'resourceVersion'=$2`,
			f.cluster, rv).Scan(&got); err != nil {
			t.Fatalf("change %s: %v", rv, err)
		}
		if got != user {
			t.Errorf("change %s is attributed to %q, want %q", rv, got, user)
		}
	}
}

func TestResponseRevisionDecidesUnderCollisions(t *testing.T) {
	f := database(t)
	e := f.engine()
	e.hub = nil
	yes := true
	at := time.Now().UTC()
	watch := func(rv, prev string) json.RawMessage {
		ev := webhookChange("informer-vwh-update-uid-1-"+rv, "unknown")
		ev.Timestamp, ev.Source, ev.UID, ev.ResourceVersion, ev.PrevResourceVersion = at, "kubernetes-informer", "uid-1", rv, prev
		return rawEvent(ev)
	}
	logged := func(user, firstSeen, produced string, finished int) LogRecord {
		ev := webhookChange("audit-"+user, user)
		done := at.Add(time.Duration(finished) * time.Millisecond)
		ev.Timestamp, ev.AuditID, ev.UID, ev.Allowed, ev.StatusCode, ev.CompletedAt = at, ev.ID, "uid-1", &yes, 200, &done
		ev.PrevResourceVersion, ev.ResourceVersion = firstSeen, produced
		return LogRecord{Event: ev}
	}
	steps := []func() error{
		func() error {
			return e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{watch("61", "60"), watch("62", "61"), watch("63", "62")})
		},
		func() error { return e.IngestLog(f.ctx, f.cluster, []LogRecord{logged("third", "60", "63", 1)}) },
		func() error { return e.IngestLog(f.ctx, f.cluster, []LogRecord{logged("second", "60", "62", 9)}) },
		func() error { return e.IngestLog(f.ctx, f.cluster, []LogRecord{logged("first", "60", "61", 5)}) },
		func() error {
			return e.IngestLog(f.ctx, f.cluster, []LogRecord{logged("fifth", "63", "65", 2), logged("fourth", "63", "64", 8)})
		},
		func() error {
			return e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{watch("64", "63"), watch("65", "64")})
		},
	}
	for i, step := range steps {
		if err := step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	changeAuthors(t, f, map[string]string{"61": "first", "62": "second", "63": "third", "64": "fourth", "65": "fifth"})
	f.counts(t, 5, 0, 0)
}

func TestWithoutIdentifiersChangesFollowTheirOrderNotTheClock(t *testing.T) {
	f := database(t)
	e := f.engine()
	e.hub = nil
	yes := true
	at := time.Now().UTC()
	behind := -2 * time.Second
	watch := func(rv string, seen time.Duration) json.RawMessage {
		ev := webhookChange("informer-vwh-update-uid-1-"+rv, "unknown")
		ev.Timestamp, ev.Source, ev.UID, ev.ResourceVersion = at.Add(behind+seen), "kubernetes-informer", "uid-1", rv
		return rawEvent(ev)
	}
	logged := func(user string, received time.Duration) LogRecord {
		ev := webhookChange("audit-"+user, user)
		done := at.Add(received + 5*time.Millisecond)
		ev.Timestamp, ev.AuditID, ev.Allowed, ev.StatusCode, ev.CompletedAt = at.Add(received), ev.ID, &yes, 200, &done
		return LogRecord{Event: ev}
	}
	steps := []func() error{
		func() error {
			return e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{
				watch("51", 10*time.Millisecond), watch("52", 410*time.Millisecond)})
		},
		func() error {
			return e.IngestLog(f.ctx, f.cluster, []LogRecord{logged("a.first", 0), logged("b.second", 400*time.Millisecond)})
		},
		func() error {
			return e.IngestLog(f.ctx, f.cluster, []LogRecord{logged("c.third", 800*time.Millisecond), logged("d.fourth", 1200*time.Millisecond)})
		},
		func() error {
			return e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{
				watch("53", 810*time.Millisecond), watch("54", 1210*time.Millisecond)})
		},
	}
	for i, step := range steps {
		if err := step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	changeAuthors(t, f, map[string]string{"51": "a.first", "52": "b.second", "53": "c.third", "54": "d.fourth"})
	f.counts(t, 4, 0, 0)
}

func TestConcurrentWatchAndLogStoreOneEvent(t *testing.T) {
	f := database(t)
	replicas := []*Engine{f.engine(), f.engine()}
	for _, e := range replicas {
		e.hub = nil
	}
	yes := true
	const n = 24
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("hook-%d", i)
		seen := webhookChange("informer-"+name, "unknown")
		seen.Name, seen.Source, seen.UID = name, "kubernetes-informer", "uid-"+name
		logged := webhookChange("audit-"+name, "m.ivanova")
		logged.Name, logged.AuditID, logged.Allowed, logged.StatusCode = name, "audit-"+name, &yes, 200
		wg.Add(2)
		go func() {
			defer wg.Done()
			errs <- replicas[0].IngestEvents(f.ctx, f.cluster, []json.RawMessage{rawEvent(seen)})
		}()
		go func() {
			defer wg.Done()
			errs <- replicas[1].IngestLog(f.ctx, f.cluster, []LogRecord{{Event: logged}})
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var events, named, complete int
	if err := f.pool.QueryRow(f.ctx,
		`SELECT COUNT(*), COUNT(*) FILTER (WHERE "user" = 'm.ivanova'),
		        COUNT(*) FILTER (WHERE origin = 'both' AND data->>'uid' LIKE 'uid-hook-%')
		   FROM audit_events WHERE cluster_id=$1`, f.cluster).Scan(&events, &named, &complete); err != nil {
		t.Fatal(err)
	}
	if events != n || named != n || complete != n {
		t.Fatalf("%d changes gave %d events, %d with the user, %d merged", n, events, named, complete)
	}
}

type statementCounter struct{ n atomic.Int64 }

func (c *statementCounter) TraceQueryStart(ctx context.Context, _ *pgx.Conn, _ pgx.TraceQueryStartData) context.Context {
	c.n.Add(1)
	return ctx
}

func (c *statementCounter) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestRedeliveryCostsOneStatementPerBatch(t *testing.T) {
	f := database(t)
	cfg, err := pgxpool.ParseConfig(os.Getenv("AUDIT_TEST_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	counter := &statementCounter{}
	cfg.ConnConfig.Tracer = counter
	pool, err := pgxpool.NewWithConfig(f.ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if f.st, err = store.NewFromPool(f.ctx, pool); err != nil {
		t.Fatal(err)
	}
	e := f.engine(eachRule())
	e.hub = nil
	raws := make([]json.RawMessage, 20)
	for i := range raws {
		raws[i] = rawEvent(event(fmt.Sprintf("again-%d", i)))
	}
	if err := e.IngestEvents(f.ctx, f.cluster, raws); err != nil {
		t.Fatal(err)
	}
	before := counter.n.Load()
	if err := e.IngestEvents(f.ctx, f.cluster, raws); err != nil {
		t.Fatal(err)
	}
	if spent := counter.n.Load() - before; spent > 2 {
		t.Fatalf("redelivering 20 processed events ran %d statements", spent)
	}
	f.counts(t, 20, 20, 20)
}

func TestAmbiguousWebhookChangeIsUnconfirmedLiveAndStored(t *testing.T) {
	f := database(t)
	e := f.engine()
	at := time.Now().UTC()
	watched := func(id string, offset time.Duration) json.RawMessage {
		ev := webhookChange(id, "unknown")
		ev.Timestamp, ev.Source, ev.ServiceAccount = at.Add(offset), sourceInformer, "unknown"
		return rawEvent(ev)
	}
	if err := e.IngestEvents(f.ctx, f.cluster, []json.RawMessage{watched("informer-a", time.Second), watched("informer-b", 3*time.Second)}); err != nil {
		t.Fatal(err)
	}
	logged := webhookChange("audit-ambiguous", "m.ivanova")
	logged.Timestamp = at
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{{Event: logged}}); err != nil {
		t.Fatal(err)
	}
	var stored int
	if err := f.pool.QueryRow(f.ctx, `SELECT COUNT(*) FROM audit_events WHERE cluster_id=$1 AND "user"='m.ivanova' AND data->>'attribution'=$2`, f.cluster, auditrules.AttributionUnconfirmed).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != 1 {
		t.Fatalf("stored unconfirmed events = %d", stored)
	}
	live := false
	for _, ev := range f.pub.events {
		if ev.Type == "audit_event_update" && strings.Contains(string(ev.Data), `"attribution":"unconfirmed"`) && strings.Contains(string(ev.Data), `"user":"m.ivanova"`) {
			live = true
		}
	}
	if !live {
		t.Fatalf("live update hides the unconfirmed author: %d events published", len(f.pub.events))
	}
}

func TestRecordProcessedBeforeTheUpgradeIsNotStoredAgain(t *testing.T) {
	f := database(t)
	yes := true
	record := func(auditID string, at time.Time) LogRecord {
		ev := event(auditID)
		ev.Kind, ev.Resource, ev.Name, ev.User = auditrules.KindGet, "secrets", "db", "a.sokolov"
		ev.Timestamp, ev.AuditID, ev.Allowed, ev.StatusCode = at, auditID, &yes, 200
		return LogRecord{Event: ev}
	}
	if err := f.st.Cluster(f.cluster).WithAuditEvent(f.ctx, "apilog:audit-old", func(_ *store.Scoped, state *store.AuditState) error {
		state.Admitted = true
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UTC().Add(-time.Minute)
	e := f.engine()
	e.hub = nil
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{record("audit-old", before)}); err != nil {
		t.Fatal(err)
	}
	f.counts(t, 0, 0, 0)
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{record("audit-old", time.Now().UTC())}); err != nil {
		t.Fatal(err)
	}
	f.counts(t, 1, 0, 0)
}
