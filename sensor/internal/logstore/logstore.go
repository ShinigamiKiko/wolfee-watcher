package logstore

import (
	"context"
	"fmt"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/wolfee-watcher/sensor/internal/central"
)

const opTimeout = 5 * time.Second

type LogLine = central.LogLine

type Store struct {
	central *central.Client
	client  kubernetes.Interface
}

func New(c *central.Client, client kubernetes.Interface) *Store {
	return &Store{central: c, client: client}
}

func (s *Store) Get(ctx context.Context, ns, pod, container string, sinceSeconds int64) ([]LogLine, error) {
	opCtx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	lines, err := s.central.PullLogs(opCtx, ns, pod, container, sinceSeconds)
	if err != nil {
		return nil, fmt.Errorf("pull logs from kvisior: %w", err)
	}
	if len(lines) == 0 {
		return nil, nil
	}
	return lines, nil
}

func (s *Store) SetSnapshotCache(ctx context.Context, gz []byte, etag string) error {
	opCtx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	return s.central.PushSnapshotCache(opCtx, gz, etag)
}

func (s *Store) GetSnapshotCache(ctx context.Context) ([]byte, string, error) {
	opCtx, cancel := context.WithTimeout(ctx, opTimeout)
	defer cancel()
	return s.central.PullSnapshotCache(opCtx)
}
