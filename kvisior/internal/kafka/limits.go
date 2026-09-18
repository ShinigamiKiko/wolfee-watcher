package kafka

import "github.com/twmb/franz-go/pkg/kgo"

func FetchLimits() []kgo.Opt {
	return []kgo.Opt{
		kgo.FetchMaxBytes(8 << 20),
		kgo.FetchMaxPartitionBytes(1 << 20),
		kgo.BrokerMaxReadBytes(16 << 20),
		kgo.MaxConcurrentFetches(2),
	}
}
