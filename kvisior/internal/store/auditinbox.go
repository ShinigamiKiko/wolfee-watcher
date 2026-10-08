package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var ErrAuditBacklogFull = errors.New("cluster audit backlog full")

var jsonNUL = []byte(`\u0000`)

func StorableJSON(raw []byte) []byte {
	if !bytes.Contains(raw, jsonNUL) {
		return raw
	}
	out := make([]byte, 0, len(raw)+16)
	for i := 0; i < len(raw); i++ {
		if raw[i] != '\\' || i+1 >= len(raw) {
			out = append(out, raw[i])
			continue
		}
		if raw[i+1] == 'u' && i+6 <= len(raw) && bytes.Equal(raw[i:i+6], jsonNUL) {
			out = append(out, "\\ufffd"...)
			i += 5
			continue
		}
		out = append(out, raw[i], raw[i+1])
		i++
	}
	return out
}

type AuditBatch struct {
	ID            int64
	Cluster, Kind string
	Payload       []json.RawMessage
	CreatedAt     time.Time
	Attempts      int
}
type AuditInboxStatus struct {
	Pending     int64      `json:"pending"`
	Oldest      *time.Time `json:"oldest,omitempty"`
	MaxAttempts int        `json:"maxAttempts"`
}

func (s *Store) EnqueueAudit(ctx context.Context, cluster, kind string, records []json.RawMessage, maxPending int) error {
	if !ValidClusterID(cluster) || (kind != "events" && kind != "log") {
		return fmt.Errorf("invalid audit batch identity")
	}
	s = s.forCluster(cluster)
	payload, err := json.Marshal(records)
	if err != nil {
		return err
	}
	payload = StorableJSON(payload)
	hash := sha256.Sum256(payload)
	key := hex.EncodeToString(hash[:])
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.Background())
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "audit-inbox-admit:"+cluster); err != nil {
		return err
	}
	var exists bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM audit_inbox WHERE cluster_id=$1 AND kind=$2 AND batch_key=$3)`, cluster, kind, key).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return tx.Commit(ctx)
	}
	if maxPending > 0 {
		var count int
		if err = tx.QueryRow(ctx, `SELECT COUNT(*) FROM audit_inbox WHERE cluster_id=$1 AND processed_at IS NULL`, cluster).Scan(&count); err != nil {
			return err
		}
		if count >= maxPending {
			return ErrAuditBacklogFull
		}
	}
	if _, err = tx.Exec(ctx, `INSERT INTO audit_inbox(cluster_id,kind,batch_key,payload) VALUES($1,$2,$3,$4) ON CONFLICT DO NOTHING`, cluster, kind, key, payload); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Store) ProcessAuditBatch(ctx context.Context, process func(context.Context, AuditBatch) error) (bool, error) {
	rows, err := s.pool.Query(ctx, `WITH RECURSIVE pending AS (
		  (SELECT cluster_id FROM audit_inbox WHERE processed_at IS NULL ORDER BY cluster_id LIMIT 1)
		  UNION ALL
		  SELECT (SELECT i.cluster_id FROM audit_inbox i
		           WHERE i.processed_at IS NULL AND i.cluster_id > p.cluster_id ORDER BY i.cluster_id LIMIT 1)
		    FROM pending p WHERE p.cluster_id IS NOT NULL)
		SELECT head.cluster_id FROM (SELECT cluster_id FROM pending WHERE cluster_id IS NOT NULL) p
		 CROSS JOIN LATERAL (SELECT i.cluster_id, i.id, i.next_attempt_at FROM audit_inbox i
		                      WHERE i.processed_at IS NULL AND i.cluster_id = p.cluster_id
		                      ORDER BY i.cluster_id, i.id LIMIT 1) head
		 WHERE head.next_attempt_at <= clock_timestamp()
		 ORDER BY head.id LIMIT 64`)
	if err != nil {
		return false, err
	}
	clusters := []string{}
	for rows.Next() {
		var c string
		if err = rows.Scan(&c); err != nil {
			rows.Close()
			return false, err
		}
		clusters = append(clusters, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return false, err
	}
	for _, cluster := range clusters {
		if s.Routed(cluster) {
			continue
		}
		worked, err := s.processAuditCluster(ctx, cluster, process)
		if err != nil || worked {
			return worked, err
		}
	}
	return false, nil
}
func (s *Store) processAuditCluster(ctx context.Context, cluster string, process func(context.Context, AuditBatch) error) (bool, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(context.Background())
	var locked bool
	if err = tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))`, "audit-inbox-process:"+cluster).Scan(&locked); err != nil || !locked {
		return false, err
	}
	batch := AuditBatch{Cluster: cluster}
	var payload []byte
	var ready bool
	err = tx.QueryRow(ctx, `SELECT id,kind,payload,created_at,attempts,next_attempt_at<=clock_timestamp() FROM audit_inbox WHERE cluster_id=$1 AND processed_at IS NULL ORDER BY cluster_id,id LIMIT 1 FOR UPDATE`, cluster).Scan(&batch.ID, &batch.Kind, &payload, &batch.CreatedAt, &batch.Attempts, &ready)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !ready {
		return false, nil
	}
	err = json.Unmarshal(payload, &batch.Payload)
	if err == nil {
		err = process(ctx, batch)
	}
	if err != nil {
		book, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		delay := time.Second * time.Duration(1<<min(batch.Attempts, 5))
		_, saveErr := tx.Exec(book, `UPDATE audit_inbox SET attempts=attempts+1,last_error=$2,next_attempt_at=clock_timestamp()+$3::interval WHERE id=$1`, batch.ID, inboxError(err), fmt.Sprintf("%f seconds", delay.Seconds()))
		if saveErr != nil {
			return true, saveErr
		}
		if saveErr = tx.Commit(book); saveErr != nil {
			return true, saveErr
		}
		return true, err
	}
	if _, err = tx.Exec(ctx, `UPDATE audit_inbox SET processed_at=clock_timestamp(),last_error='',payload='[]'::jsonb WHERE id=$1`, batch.ID); err != nil {
		return true, err
	}
	return true, tx.Commit(ctx)
}

func inboxError(err error) string {
	detail := strings.ToValidUTF8(strings.ReplaceAll(err.Error(), "\x00", "�"), "�")
	if len(detail) <= 1000 {
		return detail
	}
	cut := 1000
	for cut > 0 && !utf8.RuneStart(detail[cut]) {
		cut--
	}
	return detail[:cut]
}
func (s *Store) AuditInboxStatus(ctx context.Context) (AuditInboxStatus, error) {
	var status AuditInboxStatus
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*),MIN(created_at),COALESCE(MAX(attempts),0) FROM audit_inbox WHERE processed_at IS NULL`).Scan(&status.Pending, &status.Oldest, &status.MaxAttempts)
	return status, err
}
func (s *Store) AuditInboxReady(ctx context.Context) error {
	_, err := s.pool.Exec(ctx, `SELECT 1 FROM audit_inbox LIMIT 1`)
	return err
}

const auditInboxCleanChunk = 5000

func (s *Store) CleanAuditInbox(ctx context.Context) (int64, error) {
	cutoff, known := auditRetentionInterval()
	if !known {
		return 0, nil
	}
	var total int64
	for {
		tag, err := s.pool.Exec(ctx, `DELETE FROM audit_inbox WHERE id IN (
		    SELECT id FROM audit_inbox WHERE processed_at < clock_timestamp()-$1::interval
		     ORDER BY processed_at LIMIT $2 FOR UPDATE SKIP LOCKED)`, cutoff, auditInboxCleanChunk)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < auditInboxCleanChunk {
			return total, nil
		}
	}
}

func FromPool(pool *pgxpool.Pool) *Store { return &Store{pool: pool} }
