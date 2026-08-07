package recon

import (
	"testing"
	"time"
)

func TestDetectorEmitsPortScanAfterFiveUniquePorts(t *testing.T) {
	d := New()
	defer d.Stop()
	now := time.Now()

	for port := uint32(3001); port <= 3005; port++ {
		alerts := d.Observe("default", "test", "10.0.0.66", port, now)
		if port < 3005 && len(alerts) != 0 {
			t.Fatalf("port %d emitted %d alerts before threshold", port, len(alerts))
		}
		if port == 3005 {
			if len(alerts) != 1 || alerts[0].Kind != KindPortScan {
				t.Fatalf("alerts at threshold = %#v, want one port_scan", alerts)
			}
		}
	}
}
