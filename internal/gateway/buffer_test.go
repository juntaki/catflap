package gateway

import "testing"

// TestBoundedWriterHonorsIoWriterContract covers the P1 fix: Write must
// report n == len(p) and a nil error even when bytes past max are dropped.
// A short n reads as a failed write to os/exec's output copier, which
// would abort an otherwise-successful command.
func TestBoundedWriterHonorsIoWriterContract(t *testing.T) {
	w := boundedBuffer(10)
	p := make([]byte, 64)
	n, err := w.Write(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(p) {
		t.Fatalf("n = %d, want %d (full input consumed)", n, len(p))
	}
	if w.buf.Len() != 10 {
		t.Fatalf("buffered %d bytes, want 10 (capped)", w.buf.Len())
	}
	if !w.truncated {
		t.Error("expected truncated to be set")
	}

	// A second write past the cap must also report full consumption.
	n2, err2 := w.Write([]byte("more"))
	if err2 != nil || n2 != 4 {
		t.Fatalf("n2=%d err2=%v, want n2=4 err2=nil", n2, err2)
	}
}

func TestBoundedWriterUnderLimitNotTruncated(t *testing.T) {
	w := boundedBuffer(10)
	n, err := w.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("n=%d err=%v, want n=5 err=nil", n, err)
	}
	if w.truncated {
		t.Error("should not be truncated when under limit")
	}
	if w.String() != "hello" {
		t.Fatalf("got %q", w.String())
	}
}
