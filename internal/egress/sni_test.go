package egress

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// captureClientHello returns the ClientHello bytes the stdlib client emits
// for serverName.
func captureClientHello(t *testing.T, serverName string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		client := tls.Client(c1, &tls.Config{ServerName: serverName, InsecureSkipVerify: true})
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		// The handshake blocks after writing ClientHello; we only need the
		// bytes, so ignore the error.
		_ = client.HandshakeContext(ctx)
	}()

	_ = c2.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 4096)
	n, err := c2.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("read client hello: %v", err)
	}
	c2.Close()
	<-done
	return buf[:n]
}

func TestExtractSNI(t *testing.T) {
	hello := captureClientHello(t, "api.example.com")
	host, ok := ExtractSNI(hello)
	if !ok {
		t.Fatalf("ExtractSNI returned ok=false for a valid ClientHello")
	}
	if host != "api.example.com" {
		t.Fatalf("ExtractSNI = %q, want api.example.com", host)
	}
}

func TestExtractSNINonTLS(t *testing.T) {
	if _, ok := ExtractSNI([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n")); ok {
		t.Fatalf("ExtractSNI should reject non-TLS data")
	}
	if _, ok := ExtractSNI(nil); ok {
		t.Fatalf("ExtractSNI should reject empty data")
	}
}

func TestHTTPHostFromPeek(t *testing.T) {
	cases := []struct {
		name string
		data string
		want string
		ok   bool
	}{
		{"simple", "GET /x HTTP/1.1\r\nHost: example.com\r\n\r\n", "example.com", true},
		{"with-port", "POST / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n", "example.com", true},
		{"case", "GET / HTTP/1.1\r\nhOsT: Example.COM\r\n\r\n", "example.com", true},
		{"not-http", "\x16\x03\x01hello", "", false},
		{"no-host", "GET / HTTP/1.1\r\nAccept: */*\r\n\r\n", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := httpHostFromPeek([]byte(tc.data))
			if ok != tc.ok || got != tc.want {
				t.Fatalf("httpHostFromPeek(%q) = (%q,%v), want (%q,%v)", tc.data, got, ok, tc.want, tc.ok)
			}
		})
	}
}
