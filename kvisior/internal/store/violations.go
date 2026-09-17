package store

import (
	"context"
	"encoding/json"
)

func (c *Scoped) WriteViolationChecked(ctx context.Context, vtype, ruleID, ruleName, sev, ns, pod, fingerprint string, data json.RawMessage) error {
	_, err := c.s.pool.Exec(ctx,
		`INSERT INTO kvisior_violations(cluster_id,vtype,rule_id,rule_name,sev,namespace,pod,fingerprint,data,last_seen)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
		 ON CONFLICT (cluster_id,fingerprint) WHERE fingerprint != '' DO UPDATE SET
		    data      = EXCLUDED.data,
		    last_seen = NOW(),
		    state = CASE
		              WHEN kvisior_violations.state IN ('FP','ACK','DISMISSED')
		                   AND kvisior_violations.state_expires_at IS NOT NULL
		                   AND kvisior_violations.state_expires_at < NOW()
		              THEN 'ACTIVE'
		              ELSE kvisior_violations.state
		            END,
		    state_expires_at = CASE
		              WHEN kvisior_violations.state IN ('FP','ACK','DISMISSED')
		                   AND kvisior_violations.state_expires_at IS NOT NULL
		                   AND kvisior_violations.state_expires_at < NOW()
		              THEN NULL
		              ELSE kvisior_violations.state_expires_at
		            END`,
		c.id, vtype, ruleID, ruleName, sev, ns, pod, fingerprint, data,
	)
	return err
}
