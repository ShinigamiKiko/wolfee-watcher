package alerter

import (
	"encoding/json"
	"log"
	"strings"

	alertspkg "github.com/wolfee-watcher/pkg/alerts"
)

func (a *Alerter) emit(r deployRule, namespace, workload, checkID, detail string) {
	fp := strings.Join([]string{"dep", r.ID, namespace, workload, checkID}, "|")
	if !a.markFresh(fp) {
		return
	}
	name := r.Name
	if name == "" {
		name = r.ID
	}
	ns := namespace
	if ns == "" {
		ns = "—"
	}
	log.Printf("[Warn] deploy detected %s in %s/%s detail=%q", name, ns, workload, detail)
	payload, _ := json.Marshal(map[string]any{
		"namespace": namespace,
		"workload":  workload,
		"check":     checkID,
	})

	a.fwd.Send(alertspkg.AlertLog{
		DetType:     "Deploy",
		Source:      sourceTag,
		RuleID:      r.ID,
		RuleName:    name,
		Severity:    r.Sev,
		Namespace:   namespace,
		Target:      workload,
		Detail:      detail,
		Persist:     true,
		Fingerprint: fp,
		Data:        payload,
	})
}
