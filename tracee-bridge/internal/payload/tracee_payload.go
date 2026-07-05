package payload

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"

	"github.com/wolfee-watcher/tracee-bridge/internal/mapper"
)

func ParseTraceePayloadStream(r io.Reader, maxBytes int64) ([]*mapper.TraceeEvent, error) {
	br := bufio.NewReader(io.LimitReader(r, maxBytes))
	first, err := firstNonSpaceByte(br)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(br)
	switch first {
	case '[':
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		if d, ok := tok.(json.Delim); !ok || d != '[' {
			return nil, errors.New("expected array payload")
		}
		events := make([]*mapper.TraceeEvent, 0, 128)
		for dec.More() {
			var ev mapper.TraceeEvent
			if err := dec.Decode(&ev); err != nil {
				return nil, err
			}
			events = append(events, &ev)
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
		return events, nil
	case '{':
		var single mapper.TraceeEvent
		if err := dec.Decode(&single); err != nil {
			return nil, err
		}
		return []*mapper.TraceeEvent{&single}, nil
	default:
		return nil, errors.New("payload must be JSON object or array")
	}
}

func firstNonSpaceByte(br *bufio.Reader) (byte, error) {
	for {
		b, err := br.ReadByte()
		if err != nil {
			return 0, err
		}
		if b == ' ' || b == '\n' || b == '\r' || b == '\t' {
			continue
		}
		if err := br.UnreadByte(); err != nil {
			return 0, err
		}
		return b, nil
	}
}
