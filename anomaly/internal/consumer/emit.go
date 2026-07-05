package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	alertspkg "github.com/wolfee-watcher/pkg/alerts"
)

func (c *Consumer) emit(ctx context.Context, a *AnomalyEvent, extID string) {
	data, marshalErr := json.Marshal(a)
	if marshalErr != nil {
		log.Printf("[consumer] marshal anomaly event: %v", marshalErr)
		return
	}
	var id int64
	err := c.pool.QueryRow(ctx,
		`INSERT INTO anomaly_events (ts, kind, data, ext_id)
		 VALUES ($1,$2,$3,$4)
		 ON CONFLICT (ext_id) DO NOTHING
		 RETURNING id`,
		a.Ts, string(a.Kind), data, extID,
	).Scan(&id)
	if err != nil {

		if errors.Is(err, pgx.ErrNoRows) {
			return
		}
		log.Printf("[consumer] INSERT anomaly_events error: %v", err)
		return
	}
	a.ID = strconv.FormatInt(id, 10)

	dst := a.DstIP
	if a.DstService != "" {
		dst = a.DstService + " (" + a.DstIP + ")"
	}
	if dst == "" {
		dst = a.Detail
	}
	log.Printf("[consumer] %s %s/%s → %s", a.Kind, a.SrcNamespace, a.SrcDeployment, dst)

	target := a.SrcPod
	if target == "" {
		target = a.SrcDeployment
	}
	detail := a.Detail
	if detail == "" {
		detail = dst
	}
	log.Printf("[Warn] anomaly detected %s in %s/%s detail=%q", a.Kind, a.SrcNamespace, target, detail)
	payload, err := json.Marshal(a)
	if err != nil {
		log.Printf("[consumer] marshal alert payload: %v — falling back to pre-ID snapshot", err)
		payload = data
	}

	c.fwd.Send(alertspkg.AlertLog{
		DetType:     "Anomaly",
		Source:      "anomaly-detector",
		RuleName:    string(a.Kind),
		Namespace:   a.SrcNamespace,
		Target:      target,
		Syscall:     a.Syscall,
		Detail:      detail,
		Persist:     true,
		Fingerprint: a.SrcNamespace + "/" + a.SrcPod + "/" + string(a.Kind) + "/" + a.DstIP + a.dedupExtra(),
		Data:        payload,
	})

	rawWithID, marshalErr := json.Marshal(a)
	if marshalErr != nil {
		log.Printf("[consumer] marshal broadcast event: %v", marshalErr)
		return
	}
	c.bcast.Broadcast(rawWithID)
	if c.notifier != nil {
		c.notifier.Notify(a)
	}
}

const dedupWindow = 5 * time.Minute

func (a *AnomalyEvent) dedupExtra() string {
	switch a.Kind {
	case KindUnexpectedBinary, KindBinaryTampering:
		return a.Detail
	default:
		return ""
	}
}

func (c *Consumer) isDuplicate(a *AnomalyEvent) bool {

	key := a.SrcNamespace + "/" + a.SrcPod + "/" + a.SrcProcess + "/" + a.Syscall + "/" + string(a.Kind)
	now := time.Now()
	c.dedupMu.Lock()
	defer c.dedupMu.Unlock()
	for k, t := range c.dedupSeen {
		if now.Sub(t) > dedupWindow {
			delete(c.dedupSeen, k)
		}
	}
	if last, ok := c.dedupSeen[key]; ok && now.Sub(last) < dedupWindow {
		return true
	}
	c.dedupSeen[key] = now
	return false
}
