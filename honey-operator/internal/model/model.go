package model

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

type HoneypotSpec struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Services  []string `json:"services"`
}

type HoneypotStatus struct {
	Name       string    `json:"name"`
	Namespace  string    `json:"namespace"`
	Services   []string  `json:"services"`
	ClusterIP  string    `json:"clusterIP"`
	Phase      string    `json:"phase"`
	CreatedAt  time.Time `json:"createdAt"`
	EventCount int       `json:"eventCount"`
}

type HoneypotEvent struct {
	Timestamp string `json:"timestamp"`
	Server    string `json:"server"`
	SrcIP     string `json:"src_ip"`
	SrcPort   string `json:"src_port"`
	DestIP    string `json:"dest_ip"`
	DestPort  string `json:"dest_port"`
	Action    string `json:"action"`
	Status    string `json:"status"`
	Data      string `json:"data,omitempty"`
	Username  string `json:"username,omitempty"`
	Password  string `json:"password,omitempty"`
}

type HoneypotEventsResponse struct {
	Name   string          `json:"name"`
	Events []HoneypotEvent `json:"events"`
	Total  int             `json:"total"`
}

type StreamEvent struct {
	HoneypotName string        `json:"honeypotName"`
	Namespace    string        `json:"namespace"`
	Event        HoneypotEvent `json:"event"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

func ParseLogs(raw []byte) []HoneypotEvent {
	var events []HoneypotEvent
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var ev HoneypotEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			continue
		}
		if ev.Action == "process" && ev.SrcIP == "0.0.0.0" {
			continue
		}
		events = append(events, ev)
	}
	return events
}
