package consumer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	alertspkg "github.com/wolfee-watcher/pkg/alerts"
)

const emitDBAttempts = 3

func (c *Consumer) insertAnomaly(ctx context.Context, a *AnomalyEvent, data []byte, extID string) (int64, bool, error) {
	backoff := 200 * time.Millisecond
	var lastErr error
	for attempt := 1; attempt <= emitDBAttempts; attempt++ {
		var id int64
		err := c.pool.QueryRow(ctx,
			`INSERT INTO anomaly_events (ts, kind, data, ext_id)
			 VALUES ($1,$2,$3,$4)
			 ON CONFLICT (ext_id) DO NOTHING
			 RETURNING id`,
			a.Ts, string(a.Kind), data, extID,
		).Scan(&id)
		if err == nil {
			return id, true, nil
		}
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, false, nil
		}
		lastErr = err
		if attempt == emitDBAttempts {
			break
		}
		select {
		case <-ctx.Done():
			return 0, false, ctx.Err()
		case <-time.After(backoff):
		}
		backoff *= 2
	}
	return 0, false, lastErr
}

func (c *Consumer) emit(ctx context.Context, a *AnomalyEvent, extID string) error {
	data, marshalErr := json.Marshal(a)
	if marshalErr != nil {
		log.Printf("[consumer] marshal anomaly event: %v", marshalErr)
		return nil
	}
	id, inserted, err := c.insertAnomaly(ctx, a, data, extID)
	if err != nil {
		log.Printf("[consumer] INSERT anomaly_events error after %d attempts: %v", emitDBAttempts, err)
		return fmt.Errorf("insert anomaly_events ext_id=%s: %w", extID, err)
	}
	if !inserted {
		return nil
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
		Timestamp:   a.Ts,
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
		return nil
	}
	c.bcast.Broadcast(rawWithID)
	return nil
}

const dedupWindow = 5 * time.Minute

func (a *AnomalyEvent) dedupExtra() string {
	switch a.Kind {
	case KindUnexpectedBinary, KindBinaryTampering:
		return a.Detail
	case KindSuspiciousBind, KindSuspiciousPort, KindUnexpectedListen:
		return strconv.FormatUint(uint64(a.DstPort), 10)
	default:
		return ""
	}
}

func (c *Consumer) dedupKey(a *AnomalyEvent) string {
	key := a.SrcNamespace + "/" + a.SrcPod + "/" + a.SrcProcess + "/" + a.Syscall + "/" + string(a.Kind)
	if a.DstIP != "" {
		key += "/" + a.DstIP
	}
	if extra := a.dedupExtra(); extra != "" {
		key += "/" + extra
	}
	return key
}

func (c *Consumer) isDuplicate(a *AnomalyEvent) bool {
	key := c.dedupKey(a)
	now := time.Now()
	c.dedupMu.Lock()
	defer c.dedupMu.Unlock()
	for k, t := range c.dedupSeen {
		if now.Sub(t) > dedupWindow {
			delete(c.dedupSeen, k)
		}
	}
	last, ok := c.dedupSeen[key]
	return ok && now.Sub(last) < dedupWindow
}

func (c *Consumer) markEmitted(a *AnomalyEvent) {
	key := c.dedupKey(a)
	c.dedupMu.Lock()
	c.dedupSeen[key] = time.Now()
	c.dedupMu.Unlock()
}
