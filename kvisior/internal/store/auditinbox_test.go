package store

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestStorableJSONReplacesOnlyRealNULEscapes(t *testing.T) {
	replacement := string(rune(0xfffd))
	cases := map[string][]string{
		`["plain"]`:              {"plain"},
		`["a\u0000b"]`:           {"a" + replacement + "b"},
		`["a\\u0000b"]`:          {`a\u0000b`},
		`["\\\u0000"]`:           {`\` + replacement},
		`["x\u0000","\u0000\""]`: {"x" + replacement, replacement + `"`},
	}
	for in, want := range cases {
		out := StorableJSON([]byte(in))
		if bytes.Contains(out, []byte{0}) || strings.Contains(strings.ReplaceAll(string(out), `\\`, ""), `\u0000`) {
			t.Errorf("%s: NUL left in %s", in, out)
		}
		var got []string
		if err := json.Unmarshal(out, &got); err != nil {
			t.Errorf("%s: result is not valid JSON: %v", in, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: got %q, want %q", in, got, want)
		}
	}
}
