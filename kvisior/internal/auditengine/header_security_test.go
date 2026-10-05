package auditengine

import (
	"testing"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/pkg/auditrules"
)

func TestUnverifiedProxyCannotSupplyAnOfficeAddress(t *testing.T) {
	outside := eachRule()
	outside.Spec.Kinds = []string{auditrules.KindDelete}
	outside.Spec.IPMode, outside.Spec.IPList = auditrules.IPNotIn, "10.20.0.0/16"
	outside.Normalize()
	matcher := auditrules.NewMatcher()
	matcher.Replace([]auditrules.Rule{outside})
	cases := []struct {
		name     string
		settings store.AuditProxySettings
		chain    []string
		want     string
	}{
		{
			name:  "direct, both headers forged",
			chain: []string{"10.20.14.36", "10.20.14.37", "192.0.2.77"},
			want:  "192.0.2.77",
		},
		{
			name:     "proxy adds XFF but passes a client X-Real-IP",
			settings: store.AuditProxySettings{Proxies: "203.0.113.48"},
			chain:    []string{"192.0.2.77", "10.20.14.36", "203.0.113.48"},
			want:     "203.0.113.48",
		},
		{
			name:     "verified proxy removes X-Real-IP and appends the actual XFF peer",
			settings: store.AuditProxySettings{Proxies: "203.0.113.48", HeadersSanitized: true},
			chain:    []string{"10.20.14.36", "192.0.2.77", "203.0.113.48"},
			want:     "192.0.2.77",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			trusted, err := trustedProxyNetworks(c.settings)
			if err != nil {
				t.Fatal(err)
			}
			ev := event("headers")
			ev.Kind, ev.Resource, ev.SourceIPs = auditrules.KindDelete, "secrets", c.chain
			ev.ClientIP = auditrules.ClientIP(ev.SourceIPs, trusted)
			if ev.SourceIP() != c.want {
				t.Fatalf("resolved %q, want %q", ev.SourceIP(), c.want)
			}
			if len(matcher.Match("test", &ev, false)) != 1 {
				t.Fatal("a forwarded header bypassed the outside-office rule")
			}
		})
	}
}

func TestAPILogIdentityDistinguishesRequestsWithTheSameAuditID(t *testing.T) {
	first := event("client-chosen")
	first.AuditID = first.ID
	first.Kind = auditrules.KindGet
	second := first
	second.Timestamp = first.Timestamp.Add(time.Nanosecond)
	if apiLogEventID(&first) == apiLogEventID(&second) {
		t.Fatal("two separate requests with the same client Audit-ID collide")
	}
	second = first
	second.Resource, second.Name = "secrets", "db"
	if apiLogEventID(&first) == apiLogEventID(&second) {
		t.Fatal("different objects with the same Audit-ID and timestamp collide")
	}
	second = first
	second.User = "bob"
	if apiLogEventID(&first) == apiLogEventID(&second) {
		t.Fatal("different users share the same request identity")
	}
	second = first
	second.SourceIPs = []string{"192.0.2.77"}
	if apiLogEventID(&first) == apiLogEventID(&second) {
		t.Fatal("different connection sources share the same request identity")
	}
}

func TestAPILogIdentitySurvivesReplayStagesAndPolicyChanges(t *testing.T) {
	started := event("client-chosen")
	started.AuditID, started.Kind = started.ID, auditrules.KindExec
	started.StatusCode = 200
	complete := started
	done := started.Timestamp.Add(time.Second)
	complete.CompletedAt, complete.StatusCode = &done, 500
	complete.ID, complete.ClientIP = "another-reader-id", "192.0.2.77"
	complete.UID, complete.ResourceVersion = "response-object", "42"
	if apiLogEventID(&started) != apiLogEventID(&complete) {
		t.Fatal("response stage, reader ID or enrichment changed the request identity")
	}
}

func TestReusedAuditIDStoresBothRequestsAndDeduplicatesReplay(t *testing.T) {
	f := database(t)
	rule := eachRule()
	rule.Spec.Kinds = []string{auditrules.KindGet}
	e := f.engine(rule)
	e.hub = nil
	seed := event("client-chosen")
	seed.AuditID, seed.Kind = seed.ID, auditrules.KindGet
	second := seed
	second.Timestamp = seed.Timestamp.Add(time.Nanosecond)
	second.Resource, second.Name = "secrets", "db"
	records := []LogRecord{{Event: seed}, {Event: second}}
	for i := 0; i < 2; i++ {
		if err := e.IngestLog(f.ctx, f.cluster, records); err != nil {
			t.Fatal(err)
		}
	}
	f.counts(t, 2, 2, 2)
	var ids, correlations int
	if err := f.pool.QueryRow(f.ctx,
		`SELECT COUNT(DISTINCT event_uid), COUNT(*) FILTER (WHERE data->>'auditID'=$2)
		   FROM audit_events WHERE cluster_id=$1`, f.cluster, seed.AuditID).Scan(&ids, &correlations); err != nil {
		t.Fatal(err)
	}
	if ids != 2 || correlations != 2 {
		t.Fatalf("event identities=%d correlation IDs=%d", ids, correlations)
	}
	if records[0].Event.ID != seed.ID || records[1].Event.ID != second.ID {
		t.Fatal("ingestion mutated the reader's retry payload")
	}
}

func TestConfiguredUnverifiedProxyUsesPeerThroughoutStorageAndRules(t *testing.T) {
	f := database(t)
	t.Cleanup(func() {
		if _, err := f.pool.Exec(f.ctx, "DELETE FROM audit_trusted_proxies WHERE cluster_id=$1", f.cluster); err != nil {
			t.Error(err)
		}
	})
	if err := f.st.Cluster(f.cluster).SaveAuditTrustedProxies(f.ctx, store.AuditProxySettings{
		Proxies: "203.0.113.48",
	}, "admin"); err != nil {
		t.Fatal(err)
	}
	outside := eachRule()
	outside.Alert = false
	outside.Spec.Kinds = []string{auditrules.KindDelete}
	outside.Spec.IPMode, outside.Spec.IPList = auditrules.IPNotIn, "10.20.0.0/16"
	e := f.engine(outside)
	e.hub = nil
	ev := event("forged-real-ip")
	ev.AuditID, ev.Kind, ev.Resource = ev.ID, auditrules.KindDelete, "secrets"
	ev.SourceIPs = []string{"192.0.2.77", "10.20.14.36", "203.0.113.48"}
	ev.ClientIP = "10.20.14.36"
	if err := e.IngestLog(f.ctx, f.cluster, []LogRecord{{Event: ev}}); err != nil {
		t.Fatal(err)
	}
	f.counts(t, 1, 1, 0)
	var column, data, violation string
	if err := f.pool.QueryRow(f.ctx,
		`SELECT source_ip, data->>'clientIP' FROM audit_events WHERE cluster_id=$1`,
		f.cluster).Scan(&column, &data); err != nil {
		t.Fatal(err)
	}
	if err := f.pool.QueryRow(f.ctx, `SELECT source_ip FROM audit_violations WHERE cluster_id=$1`,
		f.cluster).Scan(&violation); err != nil {
		t.Fatal(err)
	}
	if column != "203.0.113.48" || data != column || violation != column {
		t.Fatalf("forwarded address persisted: source_ip=%q clientIP=%q violation=%q", column, data, violation)
	}
}
