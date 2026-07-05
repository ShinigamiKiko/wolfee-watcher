package uibus

import (
	"context"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/twmb/franz-go/pkg/kadm"
	"github.com/twmb/franz-go/pkg/kgo"

	"github.com/wolfee-watcher/kvisior/internal/hub"
)

const Topic = "kvisior-ui-events"

type Bus struct {
	hub      *hub.Hub
	producer *kgo.Client
	brokers  []string
}

func New(ctx context.Context, h *hub.Hub, brokers []string) *Bus {
	b := &Bus{hub: h, brokers: brokers}
	if len(brokers) == 0 {
		return b
	}
	producer, err := kgo.NewClient(
		kgo.SeedBrokers(brokers...),
		kgo.DefaultProduceTopic(Topic),
		kgo.RecordDeliveryTimeout(5*time.Second),
	)
	if err != nil {
		log.Printf("[uibus] kafka producer init: %v — falling back to local-only fan-out", err)
		return b
	}
	b.producer = producer

	go func() {
		cCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		adm := kadm.NewClient(producer)
		if _, err := adm.CreateTopic(cCtx, 1, -1, nil, Topic); err != nil &&
			!strings.Contains(err.Error(), "TOPIC_ALREADY_EXISTS") {
			log.Printf("[uibus] topic ensure: %v", err)
		}
	}()
	go b.runConsumer(ctx)
	log.Printf("[uibus] kafka fan-out enabled — pushed events reach every replica's SSE hub")
	return b
}

func (b *Bus) Publish(e hub.Event) {
	if b.producer == nil {
		b.hub.Publish(e)
		return
	}
	data, err := json.Marshal(e)
	if err != nil {
		b.hub.Publish(e)
		return
	}
	b.producer.Produce(context.Background(), &kgo.Record{Value: data}, func(_ *kgo.Record, err error) {
		if err != nil {

			log.Printf("[uibus] produce error: %v — delivering locally only", err)
			b.hub.Publish(e)
		}
	})
}

func (b *Bus) runConsumer(ctx context.Context) {
	cl, err := kgo.NewClient(
		kgo.SeedBrokers(b.brokers...),
		kgo.ConsumeTopics(Topic),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtEnd()),
	)
	if err != nil {
		log.Printf("[uibus] consumer init: %v — pushed events visible on receiving replica only", err)
		return
	}
	defer cl.Close()
	for {
		if ctx.Err() != nil {
			return
		}
		fetches := cl.PollFetches(ctx)
		for _, fe := range fetches.Errors() {
			if ctx.Err() == nil {
				log.Printf("[uibus] consume error: partition=%d: %v", fe.Partition, fe.Err)
			}
		}
		fetches.EachRecord(func(r *kgo.Record) {
			var e hub.Event
			if json.Unmarshal(r.Value, &e) == nil && e.Type != "" {
				b.hub.Publish(e)
			}
		})
	}
}
