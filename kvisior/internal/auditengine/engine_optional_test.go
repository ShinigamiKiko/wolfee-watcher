package auditengine

import (
	"testing"
	"time"

	"github.com/wolfee-watcher/kvisior/internal/store"
	"github.com/wolfee-watcher/pkg/auditrules"
)

func TestWebhookMatchingAcceptsMetadataAndResponseRevisions(t *testing.T) {
	at := time.Now().UTC()
	for _, response := range []bool{false, true} {
		name := "Metadata"
		if response {
			name = "RequestResponse"
		}
		t.Run(name, func(t *testing.T) {
			done := at.Add(time.Millisecond)
			logged := auditrules.Event{
				Kind: auditrules.KindUpdate, Timestamp: at, CompletedAt: &done,
			}
			watch := auditrules.Event{
				Kind: auditrules.KindUpdate, Timestamp: done,
				UID: "object-1", ResourceVersion: "42", PrevResourceVersion: "41",
			}
			if response {
				logged.UID, logged.ResourceVersion = watch.UID, watch.ResourceVersion
			}
			watched := store.AuditTwin{
				EventUID: "watch-1", Origin: store.AuditOriginAdmission, Source: sourceInformer,
				ObjectUID: watch.UID, ResourceVersion: watch.ResourceVersion,
				PrevResourceVersion: watch.PrevResourceVersion, At: watch.Timestamp,
			}
			record := store.AuditTwin{
				EventUID: "log-1", Origin: store.AuditOriginAPILog,
				ObjectUID: logged.UID, ResourceVersion: logged.ResourceVersion,
				At: logged.Timestamp, CompletedAt: done,
			}
			if m, ok := informerTwin(&logged, []store.AuditTwin{watched}); !ok || m.uid != "watch-1" {
				t.Fatalf("log first/last matching failed: match=%+v ok=%v", m, ok)
			}
			if m, ok := logTwin(&watch, []store.AuditTwin{record}); !ok || m.uid != "log-1" {
				t.Fatalf("watch first/last matching failed: match=%+v ok=%v", m, ok)
			}
		})
	}
}

func TestRulesDoNotRequireResponseRevisions(t *testing.T) {
	plain := eachRule()
	plain.Spec.Kinds = []string{auditrules.KindUpdate}
	plain.Spec.Resources = []string{"validatingwebhookconfigurations"}
	metadata := plain
	metadata.ID = "metadata-result"
	metadata.Spec.Result = auditrules.ResultAllowed
	metadata.Spec.IPMode = auditrules.IPIn
	metadata.Spec.IPList = "10.20.0.0/16"
	plain.Normalize()
	metadata.Normalize()
	e := New(nil, nil)
	e.matcher.Replace([]auditrules.Rule{plain, metadata})
	ev := webhookChange("without-log", "unknown")
	ev.Source = sourceInformer
	if hits := e.matcher.Match("test", &ev, false); len(hits) != 1 || hits[0].ID != plain.ID {
		t.Fatalf("ordinary rules must run without an API log: %+v", hits)
	}
	yes := true
	ev.User, ev.Source, ev.SourceIPs = "alice", SourceAPILog, []string{"10.20.14.36"}
	ev.Allowed, ev.StatusCode = &yes, 200
	if hits := e.matcher.Match("test", &ev, false); len(hits) != 2 {
		t.Fatalf("Metadata must be sufficient for IP and result rules: %+v", hits)
	}
}

func TestAmbiguousTimeOnlyMatchIsUnconfirmed(t *testing.T) {
	at := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	done := at.Add(200 * time.Millisecond)
	watch := auditrules.Event{Kind: auditrules.KindCreate, Resource: "configmaps", Name: "cm", Timestamp: at.Add(time.Second), Source: sourceInformer}
	record := func(uid string, offset time.Duration) store.AuditTwin {
		return store.AuditTwin{EventUID: uid, Origin: store.AuditOriginAPILog, At: at.Add(offset), CompletedAt: done.Add(offset)}
	}
	if m, ok := logTwin(&watch, []store.AuditTwin{record("log-1", 0)}); !ok || !m.confirmed || m.attribution() != "" {
		t.Fatalf("single time-window candidate: %+v %v", m, ok)
	}
	m, ok := logTwin(&watch, []store.AuditTwin{record("log-1", 0), record("log-2", 300*time.Millisecond)})
	if !ok || m.confirmed || m.attribution() != auditrules.AttributionUnconfirmed {
		t.Fatalf("two time-window candidates: %+v %v", m, ok)
	}
	watch.UID = "obj-1"
	exact := record("log-3", 0)
	exact.ObjectUID = "obj-1"
	if m, ok := logTwin(&watch, []store.AuditTwin{exact, record("log-4", 0)}); !ok || m.uid != "log-3" || !m.confirmed {
		t.Fatalf("object UID match: %+v %v", m, ok)
	}
	logged := auditrules.Event{Kind: auditrules.KindCreate, Resource: "configmaps", Name: "cm", Timestamp: at, CompletedAt: &done}
	watched := func(uid string, offset time.Duration) store.AuditTwin {
		return store.AuditTwin{EventUID: uid, Origin: store.AuditOriginAdmission, Source: sourceInformer, At: at.Add(offset)}
	}
	if m, ok := informerTwin(&logged, []store.AuditTwin{watched("watch-1", time.Second), watched("watch-2", 2*time.Second)}); !ok || m.confirmed {
		t.Fatalf("two watch candidates: %+v %v", m, ok)
	}
}
