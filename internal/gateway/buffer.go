package gateway

import "bytes"

// boundedBuffer is a bytes.Buffer capped at n bytes (extra output dropped,
// not truncated as an error: Write always reports the full input consumed).
type boundedWriter struct {
	buf       bytes.Buffer
	max       int64
	truncated bool
}

func boundedBuffer(n int64) *boundedWriter { return &boundedWriter{max: n} }

// Write honors the io.Writer contract: n == len(p) and err == nil whenever
// nothing failed, even when bytes past max are dropped. Returning a short
// count here reads as a failed write to callers like os/exec's output
// copier, which would abort the command instead of just capping output.
func (w *boundedWriter) Write(p []byte) (int, error) {
	remain := w.max - int64(w.buf.Len())
	if remain <= 0 {
		if len(p) > 0 {
			w.truncated = true
		}
		return len(p), nil
	}
	if int64(len(p)) > remain {
		w.buf.Write(p[:remain])
		w.truncated = true
		return len(p), nil
	}
	return w.buf.Write(p)
}

func (w *boundedWriter) String() string { return w.buf.String() }
