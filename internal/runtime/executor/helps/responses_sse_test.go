package helps

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

type sseByteReader struct{ data []byte }

func (r *sseByteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}

func TestResponsesSSEMultilineCRLFUTF8(t *testing.T) {
	wire := []byte(": comment\r\nevent: response.completed\r\ndata: {\r\ndata: \"type\":\"response.completed\",\r\ndata: \"response\":{\"id\":\"合成\",\"status\":\"completed\"}}\r\n\r\n")
	for _, reader := range []io.Reader{bytes.NewReader(wire), &sseByteReader{data: wire}} {
		scanner := bufio.NewScanner(reader)
		scanner.Split(SplitResponsesSSE)
		if !scanner.Scan() {
			t.Fatalf("missing event: %v", scanner.Err())
		}
		if !bytes.Contains(scanner.Bytes(), []byte("response.completed")) {
			t.Fatalf("bad event %s", scanner.Text())
		}
		if scanner.Scan() {
			t.Fatal("extra event")
		}
		if scanner.Err() != nil {
			t.Fatal(scanner.Err())
		}
	}
	scanner := bufio.NewScanner(bytes.NewBufferString("data: {\"type\":\"response.completed\"}\n"))
	scanner.Split(SplitResponsesSSE)
	if scanner.Scan() {
		t.Fatal("EOF without separator certified final")
	}
}
