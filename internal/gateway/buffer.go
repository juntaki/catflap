package gateway

import "bytes"

// boundedBuffer is a bytes.Buffer capped at n bytes (extra output dropped).
type boundedWriter struct {
	buf bytes.Buffer
	max int64
}

func boundedBuffer(n int64) *boundedWriter { return &boundedWriter{max: n} }

func (w *boundedWriter) Write(p []byte) (int, error) {
	remain := w.max - int64(w.buf.Len())
	if remain <= 0 {
		return len(p), nil
	}
	if int64(len(p)) > remain {
		p = p[:remain]
	}
	return w.buf.Write(p)
}

func (w *boundedWriter) String() string { return w.buf.String() }
