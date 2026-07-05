package baseline

import "time"

func (s *Store) Stats() (deployments, flows int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, b := range s.baselines {
		if b != nil {
			deployments++
			flows += len(b.BaselinePeers)
		}
	}
	return
}

func (s *Store) StateMap() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := make(map[string]string, len(s.baselines))
	for k, b := range s.baselines {
		if b == nil {
			m[k] = "queued"
			continue
		}
		if b.UserLocked {
			m[k] = "user_locked"
		} else if time.Now().After(b.ObservationPeriodEnd) {
			m[k] = "locked"
		} else {
			m[k] = "observing"
		}
	}
	return m
}

type GraphEdge struct {
	Src      string `json:"src"`
	DstIP    string `json:"dst_ip"`
	DstPort  uint32 `json:"dst_port"`
	Protocol string `json:"protocol"`
	Kind     string `json:"kind"`
	DstName  string `json:"dst_name"`
}

func (s *Store) AllFlows() (nodes []string, edges []GraphEdge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make(map[string]struct{})
	for depKey, b := range s.baselines {
		if b == nil {
			continue
		}
		seen[depKey] = struct{}{}
		for peer := range b.BaselinePeers {
			if peer.IsIngress {
				continue
			}
			edges = append(edges, GraphEdge{
				Src:      depKey,
				DstIP:    peer.Entity.ID,
				DstPort:  peer.DstPort,
				Protocol: string(peer.Protocol),
				Kind:     string(peer.Entity.Type),
				DstName:  peer.Entity.Name,
			})
		}
	}
	for k := range seen {
		nodes = append(nodes, k)
	}
	return
}
