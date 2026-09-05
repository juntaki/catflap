package rpc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// marshalTestRequest marshals a fixed test frame. Request carries a Secret
// field, which trips gosec G117 (potential secret marshaling) at every
// call site; Secret here is always a hardcoded test literal, never a real
// credential, so one reviewed nolint covers every test that needs a frame.
//
//nolint:gosec // reason: test-only Request literals with fake secrets, never a real credential.
func marshalTestRequest(t *testing.T, req Request) []byte {
	t.Helper()
	raw, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

func TestReadFrameNormal(t *testing.T) {
	req, err := ReadRequest(bufio.NewReader(strings.NewReader("{\"task\":\"a\"}\n")))
	if err != nil || req.Task != "a" {
		t.Errorf("normal frame failed: %v %+v", err, req)
	}
}

func TestReadFrameOversizedWithNewline(t *testing.T) {
	big := bytes.Repeat([]byte("x"), MaxLine+1)
	big = append(big, '\n')
	_, err := ReadRequest(bufio.NewReader(bytes.NewReader(big)))
	if !errors.Is(err, errFrameTooLarge) {
		t.Errorf("oversized frame must fail fast, got %v", err)
	}
}

func TestReadFrameHugeWithoutNewline(t *testing.T) {
	// No newline at all: the old ReadBytes path would allocate it all.
	huge := bytes.NewReader(bytes.Repeat([]byte("y"), 4*MaxLine))
	_, err := ReadRequest(bufio.NewReaderSize(huge, 4096))
	if !errors.Is(err, errFrameTooLarge) {
		t.Errorf("huge newline-less input must fail at the bound, got %v", err)
	}
}

// TestReadRequestRejectsOversizedTool covers the P1 fix: an unbounded
// Tool value lands verbatim in audit records, so a client bypassing MCP
// could otherwise grow one audit line past the verifier's scan limit.
func TestReadRequestRejectsOversizedTool(t *testing.T) {
	req := Request{Task: "a", Tool: strings.Repeat("x", maxToolLen+1)}
	raw := marshalTestRequest(t, req)
	_, err := ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if !errors.Is(err, errBadRequest) {
		t.Errorf("oversized tool must be rejected, got %v", err)
	}
}

func TestReadRequestRejectsNonIdentifierTool(t *testing.T) {
	req := Request{Task: "a", Tool: "remote_exec; rm -rf /"}
	raw := marshalTestRequest(t, req)
	_, err := ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if !errors.Is(err, errBadRequest) {
		t.Errorf("non-identifier tool must be rejected, got %v", err)
	}
}

func TestReadRequestAcceptsNormalTool(t *testing.T) {
	req := Request{Task: "a", Secret: "s", Tool: ToolExec}
	raw := marshalTestRequest(t, req)
	got, err := ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil || got.Tool != ToolExec {
		t.Errorf("normal tool must pass, got %v %+v", err, got)
	}
}

func TestWriteRoundTrip(t *testing.T) {
	raw := MustRaw(ExecResult{Stdout: "hi"})
	var out ExecResult
	if err := json.Unmarshal(raw, &out); err != nil || out.Stdout != "hi" {
		t.Errorf("mustraw round trip: %v %+v", err, out)
	}
}
