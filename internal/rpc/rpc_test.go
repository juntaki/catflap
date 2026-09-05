package rpc

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

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

func TestWriteRoundTrip(t *testing.T) {
	raw := MustRaw(ExecResult{Stdout: "hi"})
	var out ExecResult
	if err := json.Unmarshal(raw, &out); err != nil || out.Stdout != "hi" {
		t.Errorf("mustraw round trip: %v %+v", err, out)
	}
}
