package consumer

import "time"

func (c *Consumer) recordMemfd(namespace, pod, pid string) {
	if pid == "" {
		pid = "unknown"
	}
	key := namespace + "/" + pod + "/" + pid
	c.memfdMu.Lock()
	c.memfdSeen[key] = memfdState{ts: time.Now(), pid: pid}
	c.memfdMu.Unlock()
}

func (c *Consumer) consumeRecentMemfd(namespace, pod, pid string) bool {
	if pid == "" {
		pid = "unknown"
	}
	key := namespace + "/" + pod + "/" + pid
	c.memfdMu.Lock()
	state, found := c.memfdSeen[key]
	if found {
		delete(c.memfdSeen, key)
	}
	c.memfdMu.Unlock()
	return found && time.Since(state.ts) <= filelessWindow
}

func (c *Consumer) cleanupMemfd() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-filelessWindow * 2)
			c.memfdMu.Lock()
			for k, s := range c.memfdSeen {
				if s.ts.Before(cutoff) {
					delete(c.memfdSeen, k)
				}
			}
			c.memfdMu.Unlock()
		}
	}
}
