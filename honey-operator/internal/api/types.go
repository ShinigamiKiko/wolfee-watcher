package api

import (
	"context"
	"time"

	"github.com/wolfee-watcher/honey-operator/internal/registry"
)

type HoneypotSpec struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Service   string   `json:"service"`
	Services  []string `json:"services"`
}

type HoneypotStatus struct {
	ID         string    `json:"id,omitempty"`
	Name       string    `json:"name"`
	Namespace  string    `json:"namespace"`
	Kind       string    `json:"kind"`
	Service    string    `json:"service,omitempty"`
	Services   []string  `json:"services"`
	Port       int32     `json:"port,omitempty"`
	ClusterIP  string    `json:"clusterIP"`
	Phase      string    `json:"phase"`
	State      string    `json:"state"`
	Image      string    `json:"image,omitempty"`
	Pods       []string  `json:"pods"`
	Legacy     bool      `json:"legacy,omitempty"`
	CreatedBy  string    `json:"createdBy,omitempty"`
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

type Hub interface {
	Subscribe() chan []byte
	Unsubscribe(chan []byte)
	Records() []registry.Record
	SetRecords([]registry.Record)
	Refresh(context.Context)
}
