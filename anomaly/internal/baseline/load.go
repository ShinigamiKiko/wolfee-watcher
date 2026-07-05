package baseline

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
)

func (s *Store) Load(ctx context.Context) error {
	if s.pool == nil {
		return nil
	}
	rows, err := s.pool.Query(ctx,
		`SELECT key, ns, dep_name, dep_id, observation_period_end, user_locked,
        baseline_peers, forbidden_peers, baseline_binaries FROM network_baselines`)
	if err != nil {
		return fmt.Errorf("baseline load: %w", err)
	}
	defer rows.Close()
	loaded := 0
	for rows.Next() {
		var b BaselineInfo
		var bpJSON, fpJSON, bbJSON []byte
		if err := rows.Scan(
			new(string), &b.Namespace, &b.DeploymentName, &b.DeploymentID,
			&b.ObservationPeriodEnd, &b.UserLocked, &bpJSON, &fpJSON, &bbJSON,
		); err != nil {
			continue
		}
		if err := json.Unmarshal(bpJSON, &b.BaselinePeers); err != nil || b.BaselinePeers == nil {
			b.BaselinePeers = make(map[Peer]struct{})
		}
		if err := json.Unmarshal(fpJSON, &b.ForbiddenPeers); err != nil || b.ForbiddenPeers == nil {
			b.ForbiddenPeers = make(map[Peer]struct{})
		}
		if err := json.Unmarshal(bbJSON, &b.BaselineBinaries); err != nil || b.BaselineBinaries == nil {
			b.BaselineBinaries = make(map[string]struct{})
		}
		s.baselines[b.Namespace+"/"+b.DeploymentName] = &b
		loaded++
	}
	log.Printf("[baseline] loaded %d deployment baselines from PostgreSQL", loaded)
	return rows.Err()
}
