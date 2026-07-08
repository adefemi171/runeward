package browser

import (
	"encoding/json"
	"testing"
)

func TestCommandRoundTrip(t *testing.T) {
	in := Command{
		Action:    "type",
		Token:     "tok-123",
		URL:       "https://example.com",
		Selector:  "#login",
		Expr:      "1+1",
		Text:      "hunter2",
		TimeoutMS: 5000,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out Command
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out != in {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}

func TestCommandOmitEmpty(t *testing.T) {
	b, err := json.Marshal(Command{Action: "ping"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)
	want := `{"action":"ping"}`
	if got != want {
		t.Fatalf("omitempty not honored:\n got %s\nwant %s", got, want)
	}
}

func TestResultRoundTrip(t *testing.T) {
	cases := []Result{
		{OK: true, Value: "hello"},
		{OK: false, Error: "boom"},
		{OK: true, Screenshot: "aGVsbG8="},
	}
	for _, in := range cases {
		b, err := json.Marshal(in)
		if err != nil {
			t.Fatalf("marshal %+v: %v", in, err)
		}
		var out Result
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("unmarshal %s: %v", b, err)
		}
		if out != in {
			t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", out, in)
		}
	}
}

func TestResultErrorOmitEmpty(t *testing.T) {
	b, err := json.Marshal(Result{OK: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := string(b), `{"ok":true}`; got != want {
		t.Fatalf("omitempty not honored:\n got %s\nwant %s", got, want)
	}
}
