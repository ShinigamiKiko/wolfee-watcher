package store

import (
	"context"
	"encoding/json"
	"time"
)

type HoneypotRecord struct {
	ID          string            `json:"id"`
	Namespace   string            `json:"namespace"`
	Name        string            `json:"name"`
	Kind        string            `json:"kind"`
	Service     string            `json:"service"`
	Port        int32             `json:"port"`
	TargetPort  int32             `json:"targetPort"`
	WorkloadUID string            `json:"workloadUid"`
	ServiceUID  string            `json:"serviceUid"`
	PolicyUID   string            `json:"policyUid"`
	ClusterIP   string            `json:"clusterIP"`
	Selector    map[string]string `json:"selector"`
	Image       string            `json:"image"`
	CreatedBy   string            `json:"createdBy"`
	CreatedAt   time.Time         `json:"createdAt"`
}

func (c *Scoped) RegisterHoneypot(ctx context.Context, rec HoneypotRecord) error {
	sel, err := json.Marshal(rec.Selector)
	if err != nil {
		return err
	}
	if rec.CreatedAt.IsZero() {
		rec.CreatedAt = time.Now().UTC()
	}
	_, err = c.s.pool.Exec(ctx,
		`INSERT INTO honeypots (id, cluster_id, namespace, name, kind, service, port, target_port,
		                        workload_uid, service_uid, policy_uid, cluster_ip, selector, image, created_by, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		 ON CONFLICT (id) DO UPDATE SET
		   workload_uid = EXCLUDED.workload_uid, service_uid = EXCLUDED.service_uid,
		   policy_uid = EXCLUDED.policy_uid, cluster_ip = EXCLUDED.cluster_ip,
		   selector = EXCLUDED.selector, image = EXCLUDED.image`,
		rec.ID, c.id, rec.Namespace, rec.Name, rec.Kind, rec.Service, rec.Port, rec.TargetPort,
		rec.WorkloadUID, rec.ServiceUID, rec.PolicyUID, rec.ClusterIP, sel, rec.Image, rec.CreatedBy, rec.CreatedAt)
	return err
}

func (c *Scoped) UnregisterHoneypot(ctx context.Context, id string) error {
	_, err := c.s.pool.Exec(ctx, `DELETE FROM honeypots WHERE cluster_id = $1 AND id = $2`, c.id, id)
	return err
}

func (c *Scoped) ListHoneypotRegistry(ctx context.Context) ([]HoneypotRecord, error) {
	rows, err := c.s.pool.Query(ctx,
		`SELECT id, namespace, name, kind, service, port, target_port, workload_uid, service_uid,
		        policy_uid, cluster_ip, selector, image, created_by, created_at
		   FROM honeypots WHERE cluster_id = $1 ORDER BY namespace, name`, c.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HoneypotRecord{}
	for rows.Next() {
		var rec HoneypotRecord
		var sel []byte
		if err := rows.Scan(&rec.ID, &rec.Namespace, &rec.Name, &rec.Kind, &rec.Service, &rec.Port, &rec.TargetPort,
			&rec.WorkloadUID, &rec.ServiceUID, &rec.PolicyUID, &rec.ClusterIP, &sel, &rec.Image, &rec.CreatedBy, &rec.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(sel, &rec.Selector)
		out = append(out, rec)
	}
	return out, rows.Err()
}
