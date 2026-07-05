package mapper

import (
	"encoding/json"
	"fmt"
	"testing"
)

func BenchmarkParseAndMapTraceeEvents(b *testing.B) {
	for _, batch := range []int{1, 10, 100, 500, 1000} {
		b.Run(fmt.Sprintf("batch_%d", batch), func(b *testing.B) {
			payload := syntheticPayload(b, batch)
			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			b.ResetTimer()

			var mapped int
			for i := 0; i < b.N; i++ {
				var events []*TraceeEvent
				if err := json.Unmarshal(payload, &events); err != nil {
					b.Fatalf("unmarshal failed: %v", err)
				}
				for _, ev := range events {
					if Map(ev) != nil {
						mapped++
					}
				}
			}
			_ = mapped
		})
	}
}

func syntheticPayload(b *testing.B, n int) []byte {
	b.Helper()

	events := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		events = append(events, map[string]any{
			"timestamp":      1711458600000000000 + int64(i),
			"hostProcessId":  3000 + i,
			"userId":         1000,
			"processName":    "curl",
			"hostName":       "node-a",
			"containerId":    "deadbeefcafebabe",
			"containerImage": "alpine:3.20",
			"containerName":  "app",
			"podName":        "api-pod",
			"podNamespace":   "prod",
			"eventName":      "connect",
			"returnValue":    0,
			"args": []map[string]any{
				{
					"name": "addr",
					"type": "trace.Pointer",
					"value": map[string]any{
						"sa_family": "AF_INET",
						"sin_addr":  "10.1.2.3",
						"sin_port":  443,
					},
				},
			},
		})
	}

	raw, err := json.Marshal(events)
	if err != nil {
		b.Fatalf("marshal payload: %v", err)
	}
	return raw
}
