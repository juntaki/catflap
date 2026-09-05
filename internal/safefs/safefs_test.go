package safefs

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixture(t *testing.T) (root, absBase string) {
	t.Helper()
	base := "testdata/safefs-case"
	_ = os.RemoveAll(base)
	if err := os.MkdirAll(base+"/root/sub", 0o750); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	write := func(p, c string) {
		t.Helper()
		if err := os.WriteFile(p, []byte(c), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(base+"/root/sub/ok.txt", "ok")
	write(base+"/outside.txt", "secret")
	if err := os.Symlink("../outside.txt", base+"/root/linkfile"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("..", base+"/root/escape"); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(base)
	if err != nil {
		t.Fatal(err)
	}
	return abs + "/root", abs
}

func TestReadLegit(t *testing.T) {
	root, _ := fixture(t)
	fs := New([]string{root})
	fh, err := fs.OpenRead(root + "/sub/ok.txt")
	if err != nil {
		t.Fatalf("legit read denied: %v", err)
	}
	defer func() { _ = fh.Close() }()
	data, truncated, err := ReadAllCapped(fh, 1<<20)
	if err != nil || truncated || string(data) != "ok" {
		t.Errorf("bad read: %q %v %v", data, truncated, err)
	}
	if _, err := fs.Stat(root + "/sub"); err != nil {
		t.Errorf("stat dir: %v", err)
	}
}

func TestReadEscapeDenied(t *testing.T) {
	root, absBase := fixture(t)
	fs := New([]string{root})
	for _, p := range []string{
		root + "/escape/outside.txt",    // intermediate symlink
		root + "/linkfile",              // final symlink
		absBase + "/outside.txt",        // outside root
		root + "/../outside.txt",        // traversal
		root + "/sub/../../outside.txt", // traversal via subdir
		"/etc/passwd",                   // elsewhere
	} {
		if fh, err := fs.OpenRead(p); err == nil {
			_ = fh.Close()
			t.Errorf("escape allowed (read): %s", p)
		}
		if _, err := fs.Stat(p); err == nil {
			t.Errorf("escape allowed (stat): %s", p)
		}
	}
}

func TestWriteMatrix(t *testing.T) {
	root, _ := fixture(t)
	full := WriteOptions{MaxSize: 1 << 20, Create: true, Overwrite: true, Atomic: true}

	t.Run("create+readback", func(t *testing.T) {
		fs := New([]string{root})
		if err := fs.WriteFile(root+"/sub/new.txt", []byte("data"), full); err != nil {
			t.Fatalf("create denied: %v", err)
		}
		fh, err := fs.OpenRead(root + "/sub/new.txt")
		if err != nil {
			t.Fatalf("readback denied: %v", err)
		}
		defer func() { _ = fh.Close() }()
		data, _, _ := ReadAllCapped(fh, 1<<20)
		if string(data) != "data" {
			t.Errorf("bad roundtrip: %q", data)
		}
	})

	t.Run("overwrite gate", func(t *testing.T) {
		fs := New([]string{root})
		noOver := WriteOptions{MaxSize: 1 << 20, Create: true}
		if err := fs.WriteFile(root+"/sub/ok.txt", []byte("x"), noOver); err == nil {
			t.Error("overwrite without grant must be denied")
		}
	})

	t.Run("create gate", func(t *testing.T) {
		fs := New([]string{root})
		noCreate := WriteOptions{MaxSize: 1 << 20, Overwrite: true, Atomic: true}
		if err := fs.WriteFile(root+"/sub/nonexistent.txt", []byte("x"), noCreate); err == nil {
			t.Error("create without grant must be denied")
		}
	})

	t.Run("concurrent create-only: exactly one wins", func(t *testing.T) {
		fs := New([]string{root})
		createOnly := WriteOptions{MaxSize: 1 << 20, Create: true, Atomic: true}
		sawLinkRace := false
		// Several rounds: losers may fail at the probe (overwrite gate)
		// or at link time (already exists) depending on interleaving —
		// both are correct denials, but exactly one create must win.
		for round := 0; round < 10; round++ {
			_ = os.Remove(root + "/sub/race.txt")
			const racers = 16
			start := make(chan struct{})
			results := make(chan error, racers)
			for i := 0; i < racers; i++ {
				go func(i int) {
					<-start
					results <- fs.WriteFile(root+"/sub/race.txt",
						[]byte(fmt.Sprintf("racer-%d", i)), createOnly)
				}(i)
			}
			close(start)
			wins := 0
			for i := 0; i < racers; i++ {
				err := <-results
				if err == nil {
					wins++
				} else if strings.Contains(err.Error(), "already exists") {
					sawLinkRace = true
				} else if !strings.Contains(err.Error(), "overwrite is not allowed") {
					t.Errorf("unexpected error: %v", err)
				}
			}
			if wins != 1 {
				t.Fatalf("round %d: %d wins, want exactly 1", round, wins)
			}
		}
		if !sawLinkRace {
			t.Error("link-time EEXIST path never exercised (race too tame?)")
		}
	})

	t.Run("default deny", func(t *testing.T) {
		fs := New([]string{root})
		if err := fs.WriteFile(root+"/sub/ok.txt", []byte("x"), WriteOptions{}); err == nil {
			t.Error("zero options must deny")
		}
	})

	t.Run("symlink escape", func(t *testing.T) {
		fs := New([]string{root})
		if err := fs.WriteFile(root+"/escape/pwned.txt", []byte("x"), full); err == nil {
			t.Error("write via intermediate symlink must be denied")
		}
		if err := fs.WriteFile(root+"/linkfile", []byte("x"), full); err == nil {
			t.Error("write via final symlink must be denied")
		}
	})

	t.Run("outside root", func(t *testing.T) {
		fs := New([]string{root})
		if err := fs.WriteFile(root+"/../outside.txt", []byte("x"), full); err == nil {
			t.Error("write outside root must be denied")
		}
	})

	t.Run("oversize", func(t *testing.T) {
		fs := New([]string{root})
		small := WriteOptions{MaxSize: 4, Create: true}
		if err := fs.WriteFile(root+"/sub/big.txt", []byte("12345"), small); err == nil {
			t.Error("oversize write must be denied")
		}
	})

	t.Run("missing parent", func(t *testing.T) {
		fs := New([]string{root})
		if err := fs.WriteFile(root+"/nodir/new.txt", []byte("x"), full); err == nil {
			t.Error("write with missing parent must be denied")
		}
	})

	t.Run("non-atomic overwrite", func(t *testing.T) {
		fs := New([]string{root})
		plain := WriteOptions{MaxSize: 1 << 20, Overwrite: true}
		if err := fs.WriteFile(root+"/sub/ok.txt", []byte("plain"), plain); err != nil {
			t.Fatalf("plain overwrite denied: %v", err)
		}
		fh, _ := fs.OpenRead(root + "/sub/ok.txt")
		defer func() { _ = fh.Close() }()
		data, _, _ := ReadAllCapped(fh, 1<<20)
		if string(data) != "plain" {
			t.Errorf("bad content: %q", data)
		}
	})

	t.Run("mode preserved on atomic replace", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("mode checks are unix-only")
		}
		fs := New([]string{root})
		p := root + "/sub/ok.txt"
		if err := os.Chmod(p, 0o400); err != nil {
			t.Fatal(err)
		}
		if err := fs.WriteFile(p, []byte("v2"), full); err != nil {
			t.Fatalf("atomic replace denied: %v", err)
		}
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o400 {
			t.Errorf("mode changed to %o, want 400", fi.Mode().Perm())
		}
	})
}
