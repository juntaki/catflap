package rpc

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"time"
)

// Tools exposed over the gateway transport.
const (
	ToolExec       = "remote_exec"
	ToolRead       = "remote_read"
	ToolStat       = "remote_stat"
	ToolWrite      = "remote_write"
	ToolPing       = "ping"
	ToolRevokeSelf = "revoke_self"
)

// MaxLine caps a single JSONL frame (1 MiB + headroom). It is the
// transport ceiling: every size limit a policy may grant MUST fit inside
// one frame, so a valid policy is always an executable policy. Larger
// payloads need chunked tools (future), not larger limits.
const MaxLine = 2 << 20

// errFrameTooLarge aborts a connection the moment a frame exceeds MaxLine.
var errFrameTooLarge = errors.New("frame too large")

// errBadRequest flags a request whose fixed fields violate protocol bounds.
// Args is exempt (validated per-tool downstream); Task/Secret/Tool are
// bounded here because they land unbounded in audit records: without this,
// a request with a huge Tool value can blow past the audit verifier's
// per-line scan limit and grow the audit file without limit.
var errBadRequest = errors.New("bad request")

const (
	maxTaskLen   = 64
	maxSecretLen = 128
	maxToolLen   = 64
)

// validate rejects Task/Secret/Tool values that can't be legitimate: Tool
// is restricted to a plain identifier since it is echoed into audit
// records verbatim, and Task/Secret are bounded to their expected shape.
func (r Request) validate() error {
	if len(r.Task) > maxTaskLen || len(r.Secret) > maxSecretLen || len(r.Tool) > maxToolLen {
		return errBadRequest
	}
	for i := 0; i < len(r.Tool); i++ {
		c := r.Tool[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '_' || c == '.':
		default:
			return errBadRequest
		}
	}
	return nil
}

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
	Stdout          string `json:"stdout"`
	Stderr          string `json:"stderr"`
	ExitCode        int    `json:"exit_code"`
	StdoutTruncated bool   `json:"stdout_truncated,omitempty"`
	StderrTruncated bool   `json:"stderr_truncated,omitempty"`
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

type PingResult struct {
	Task string `json:"task"`
}

type RevokeSelfResult struct {
	Revoked bool `json:"revoked"`
}

// writeFrame marshals v as one JSONL frame, refusing to emit anything
// over MaxLine. The receiver enforces the same bound incrementally, so an
// oversized payload fails cleanly here instead of killing the connection
// mid-stream.
func writeFrame(v any) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(raw)+1 > MaxLine {
		return nil, errFrameTooLarge
	}
	return append(raw, '\n'), nil
}

// WriteRequest writes one JSONL frame with a write deadline.
func WriteRequest(c net.Conn, req Request) error {
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	raw, err := writeFrame(req)
	if err != nil {
		return err
	}
	_, err = c.Write(raw)
	return err
}

// WriteResponse writes one JSONL frame.
func WriteResponse(c net.Conn, res Response) error {
	_ = c.SetWriteDeadline(time.Now().Add(30 * time.Second))
	raw, err := writeFrame(res)
	if err != nil {
		return err
	}
	_, err = c.Write(raw)
	return err
}

// readFrame reads one newline-terminated JSONL frame, enforcing MaxLine
// incrementally: the bound is checked before each append, so at most
// MaxLine bytes are ever allocated for one frame, and the connection is
// abandoned the instant the bound is exceeded — with or without a newline.
func readFrame(r *bufio.Reader) ([]byte, error) {
	var frame []byte
	for {
		chunk, err := r.ReadSlice('\n')
		if len(frame)+len(chunk) > MaxLine {
			return nil, errFrameTooLarge
		}
		frame = append(frame, chunk...)
		if err == nil {
			return frame, nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		return nil, err
	}
}

// ReadRequest reads one JSONL frame.
func ReadRequest(r *bufio.Reader) (Request, error) {
	var req Request
	line, err := readFrame(r)
	if err != nil {
		return req, err
	}
	if err := json.Unmarshal(line, &req); err != nil {
		return req, err
	}
	if err := req.validate(); err != nil {
		return req, err
	}
	return req, nil
}

// ReadResponse reads one JSONL frame.
func ReadResponse(r *bufio.Reader) (Response, error) {
	var res Response
	_ = struct{}{}
	line, err := readFrame(r)
	if err != nil {
		return res, err
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
