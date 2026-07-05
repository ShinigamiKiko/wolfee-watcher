package api

import "time"

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
	ID        string `json:"id"`
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

type ErrorResponse struct {
	Error string `json:"error"`
}

type Broadcaster interface {
	Subscribe() chan []byte
	Unsubscribe(chan []byte)
}
