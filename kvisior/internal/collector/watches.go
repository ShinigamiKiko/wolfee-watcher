package collector

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"
)

const (
	watchRetryBase   = 30 * time.Second
	watchMaxAttempts = 5
	watchMaxWaitGens = 5
)

type podState int

const (
	podUnknown podState = iota
	podRunning
	podFinished
	podAbsent
)

type pendingWatch struct {
	gen      int
	attempts int
	next     time.Time
}

type podPhases struct {
	ready  bool
	gen    int
	phases map[string]string
}

func (p *podPhases) update(snapshot json.RawMessage) error {
	var body struct {
		Pods []struct {
			Metadata struct {
				Name      string `json:"name"`
				Namespace string `json:"namespace"`
			} `json:"metadata"`
			Status struct {
				Phase string `json:"phase"`
			} `json:"status"`
		} `json:"pods"`
	}
	if err := json.Unmarshal(snapshot, &body); err != nil {
		return err
	}
	phases := make(map[string]string, len(body.Pods))
	for _, pod := range body.Pods {
		phases[pod.Metadata.Namespace+"/"+pod.Metadata.Name] = pod.Status.Phase
	}
	p.phases = phases
	p.ready = true
	p.gen++
	return nil
}

func (p *podPhases) state(key string) podState {
	if !p.ready {
		return podUnknown
	}
	phase, ok := p.phases[key]
	switch {
	case !ok:
		return podAbsent
	case phase == "Running":
		return podRunning
	case phase == "Pending" || phase == "":
		return podUnknown
	default:
		return podFinished
	}
}

func (a *Aggregator) queueWatch(ns, pod string) {
	key := ns + "/" + pod
	if _, ok := a.pendingWatches[key]; ok {
		return
	}
	a.pendingWatches[key] = &pendingWatch{gen: a.pods.gen}
}

func (a *Aggregator) processWatches(ctx context.Context, now time.Time) {
	for key, p := range a.pendingWatches {
		switch a.pods.state(key) {
		case podUnknown:
			if a.pods.ready && a.pods.gen-p.gen > watchMaxWaitGens {
				delete(a.pendingWatches, key)
			}
		case podFinished:
			delete(a.pendingWatches, key)
		case podAbsent:
			if a.pods.gen > p.gen {
				delete(a.pendingWatches, key)
			}
		case podRunning:
			if now.Before(p.next) {
				continue
			}
			parts := strings.SplitN(key, "/", 2)
			err := a.startForensicWatch(ctx, parts[0], parts[1])
			if err == nil {
				delete(a.pendingWatches, key)
				continue
			}
			p.attempts++
			if p.attempts == 1 {
				log.Printf("[collector/anomaly] start forensic watch %s: %v; retrying while the pod runs", key, err)
			}
			if p.attempts >= watchMaxAttempts {
				log.Printf("[collector/anomaly] gave up starting forensic watch %s after %d attempts: %v", key, p.attempts, err)
				delete(a.pendingWatches, key)
				continue
			}
			p.next = now.Add(watchRetryBase << (p.attempts - 1))
		}
	}
}
