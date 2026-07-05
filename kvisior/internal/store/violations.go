package store

import (
	"context"
	"encoding/json"
)

func (s *Store) WriteViolationChecked(ctx context.Context, vtype, ruleID, ruleName, sev, ns, pod, fingerprint string, data json.RawMessage) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO kvisior_violations(vtype,rule_id,rule_name,sev,namespace,pod,fingerprint,data,last_seen)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
		 ON CONFLICT (fingerprint) WHERE fingerprint != '' DO UPDATE SET
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
		vtype, ruleID, ruleName, sev, ns, pod, fingerprint, data,
	)
	return err
}
