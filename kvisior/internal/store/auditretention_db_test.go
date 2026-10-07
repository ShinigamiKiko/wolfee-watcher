package store

import (
	"errors"
	"testing"
	"time"
)

func TestAuditRetentionIsOwnedByTheHub(t *testing.T) {
	ctx, pool, st, _ := silenceFixture(t)
	if ready, err := st.tableReady(ctx, pool, "platform_settings"); err != nil || !ready {
		t.Skip("database is not migrated to 0018")
	}
	reset := func() {
		pool.Exec(ctx, `DELETE FROM platform_settings WHERE key = $1`, auditRetentionKey)
		ConfigureAuditRetentionWriter(false)
		SetAuditRetention(14 * 24 * time.Hour)
		auditRetentionKnown.Store(false)
	}
	reset()
	t.Cleanup(reset)

	if err := st.LoadAuditRetention(ctx); err != nil {
		t.Fatal(err)
	}
	if _, known := auditSweepRetention(); known {
		t.Fatal("an edge must not sweep before the hub stored a retention")
	}
	if _, err := st.UpdateAuditRetention(ctx, 48, "edge-admin"); !errors.Is(err, ErrAuditRetentionReadOnly) {
		t.Fatalf("edge update err=%v", err)
	}

	ConfigureAuditRetentionWriter(true)
	SetAuditRetention(10 * 24 * time.Hour)
	if err := st.LoadAuditRetention(ctx); err != nil {
		t.Fatal(err)
	}
	if keep, known := auditSweepRetention(); !known || keep != 10*24*time.Hour {
		t.Fatalf("hub seed keep=%v known=%v", keep, known)
	}
	if _, err := st.UpdateAuditRetention(ctx, 12, "admin"); !errors.Is(err, ErrAuditRetentionInvalid) {
		t.Fatalf("too short retention err=%v", err)
	}
	if _, err := st.UpdateAuditRetention(ctx, 31*24, "admin"); !errors.Is(err, ErrAuditRetentionInvalid) {
		t.Fatalf("too long retention err=%v", err)
	}
	setting, err := st.UpdateAuditRetention(ctx, 48, "admin")
	if err != nil || setting.Hours != 48 || setting.UpdatedBy != "admin" || !setting.Editable {
		t.Fatalf("update %+v err=%v", setting, err)
	}

	ConfigureAuditRetentionWriter(false)
	SetAuditRetention(14 * 24 * time.Hour)
	auditRetentionKnown.Store(false)
	if err := st.LoadAuditRetention(ctx); err != nil {
		t.Fatal(err)
	}
	if keep, known := auditSweepRetention(); !known || keep != 48*time.Hour {
		t.Fatalf("edge read keep=%v known=%v", keep, known)
	}
	view, err := st.AuditRetentionSetting(ctx)
	if err != nil || view.Hours != 48 || view.Editable || !view.Synced {
		t.Fatalf("edge view %+v err=%v", view, err)
	}
}
