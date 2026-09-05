package rpc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"time"
)

// Tools exposed over the gateway transport.
const (
	ToolExec  = "remote_exec"
	ToolRead  = "remote_read"
	ToolStat  = "remote_stat"
	ToolWrite = "remote_write"
)

// MaxLine caps a single JSONL frame (1 MiB + headroom).
const MaxLine = 2 << 20

// Request is one gateway call. Task+Secret authenticate the task;
// the Tailcat layer underneath authenticates the client identity.
type Request struct {
	Task   string          `json:"task"`
	Secret string          `json:"secret"`
	ID     int64           `json:"id"`
	Tool   string          `json:"tool"`
	Args   json.RawMessage `json:"args"`
}

// Response answers a Request by ID.
type Response struct {
	ID     int64           `json:"id"`
	OK     bool            `json:"ok"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`
}

type ExecArgs struct {
	// Command is a bare executable name or absolute path; Args are passed
	// directly to it with no shell. Shell metacharacters are inert data.
	Command   string   `json:"command"`
	Args      []string `json:"args,omitempty"`
	TimeoutMs int      `json:"timeout_ms,omitempty"`
}

type ExecResult struct {
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exit_code"`
}

type ReadArgs struct {
	Path string `json:"path"`
}

type ReadResult struct {
	Content   string `json:"content"`
	Truncated bool   `json:"truncated"`
	Size      int64  `json:"size"`
}

type StatArgs struct {
	Path string `json:"path"`
}

type StatResult struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	Mode    string `json:"mode"`
	ModTime string `json:"mod_time"`
	IsDir   bool   `json:"is_dir"`
}

type WriteArgs struct {
	// Path is the destination inside the file.write grant; Content is the
	// full replacement bytes (UTF-8 text in v0.2; binary comes later).
	Path    string `json:"path"`
	Content string `json:"content"`
}

type WriteResult struct {
	Size    int64 `json:"size"`
	Created bool  `json:"created"`
}

// WriteRequest writes one JSONL frame with a write deadline.
func WriteRequest(c net.Conn, req Request) error {
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	//nolint:gosec // reason: the secret travels here by design — it is the RPC half of the task credential, and the server (not the token) is authoritative for expiry/policy.
	raw, err := json.Marshal(req)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	_, err = c.Write(raw)
	return err
}

// WriteResponse writes one JSONL frame.
func WriteResponse(c net.Conn, res Response) error {
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	raw, err := json.Marshal(res)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	_, err = c.Write(raw)
	return err
}

// ReadRequest reads one JSONL frame.
func ReadRequest(r *bufio.Reader) (Request, error) {
	var req Request
	line, err := r.ReadBytes('\n')
	if err != nil {
		return req, err
	}
	if len(line) > MaxLine {
		return req, fmt.Errorf("frame too large")
	}
	if err := json.Unmarshal(line, &req); err != nil {
		return req, err
	}
	return req, nil
}

// ReadResponse reads one JSONL frame.
func ReadResponse(r *bufio.Reader) (Response, error) {
	var res Response
	_ = struct{}{}
	line, err := r.ReadBytes('\n')
	if err != nil {
		return res, err
	}
	if len(line) > MaxLine {
		return res, fmt.Errorf("frame too large")
	}
	if err := json.Unmarshal(line, &res); err != nil {
		return res, err
	}
	return res, nil
}

func MustRaw(v any) json.RawMessage {
	// Callers pass marshal-safe gateway result structs. On the impossible
	// failure, return a fixed error payload (a literal, so encoding itself
	// cannot fail) rather than silently dropping the call.
	raw, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{"error":"result encoding failed"}`)
	}
	return raw
}
