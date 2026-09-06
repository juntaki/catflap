package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/juntaki/catflap/internal/audit"
	"github.com/juntaki/catflap/internal/pair"
	"github.com/juntaki/catflap/internal/sshhost"
	"github.com/juntaki/catflap/internal/transport/local"
	tct "github.com/juntaki/catflap/internal/transport/tailcat"
)

// Share is Catflap's core command: grant a temporary SSH login to
// whoever holds the printed pairing code, for the given TTL, and
// nothing else. There is no policy, no capability file, no admin API,
// and no grant/tasks/revoke surface — an ephemeral SSH endpoint IS the
// product, and Ctrl-C (or the TTL) is how it ends.
func Share(args []string) int {
	fs := flag.NewFlagSet("share", flag.ContinueOnError)
	ttlFlag := fs.String("ttl", "30m", "how long this machine is reachable, e.g. 30m")
	pairingTTLFlag := fs.String("pairing-ttl", pair.DefaultCodeTTL.String(), "how long the pairing code stays claimable (clamped to --ttl and to a 10m ceiling)")
	transportFlag := fs.String("transport", "tailcat", "transport: tailcat | local")
	auditDir := fs.String("audit", DefaultAuditDir(), "audit JSONL directory (empty disables file audit)")
	verbose := fs.Bool("verbose", false, "verbose transport logging")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	ttl, err := time.ParseDuration(*ttlFlag)
	if err != nil || ttl <= 0 {
		fmt.Fprintf(os.Stderr, "invalid --ttl %q\n", *ttlFlag)
		return 1
	}
	pairingTTL, err := time.ParseDuration(*pairingTTLFlag)
	if err != nil || pairingTTL <= 0 {
		fmt.Fprintf(os.Stderr, "invalid --pairing-ttl %q\n", *pairingTTLFlag)
		return 1
	}
	if *transportFlag != "tailcat" && *transportFlag != "local" {
		fmt.Fprintf(os.Stderr, "unknown transport %q (tailcat|local)\n", *transportFlag)
		return 1
	}

	ctx, stopSig := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stopSig()

	taskID := sshhost.NewID()
	alog, err := audit.Open(*auditDir, taskID, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "audit: %v\n", err)
		return 1
	}
	task, err := sshhost.NewTask(ctx, taskID, ttl, alog)
	if err != nil {
		fmt.Fprintf(os.Stderr, "mint task: %v\n", err)
		_ = alog.Close()
		return 1
	}
	alog.Log("task.create", nil, "active", nil, 0)

	var endpoint string
	switch *transportFlag {
	case "tailcat":
		s, serr := tct.Serve(task.Handler(), nil, *verbose) // nil allow: open network layer; SSH publickey auth is the real gate — see package doc.
		if serr != nil {
			fmt.Fprintf(os.Stderr, "start task server: %v\n", serr)
			task.Stop("failed")
			return 1
		}
		task.OnStopFunc(func() { _ = s.Close() })
		endpoint = s.Addr()
	case "local":
		s, serr := local.Serve(task.Handler())
		if serr != nil {
			fmt.Fprintf(os.Stderr, "start task server: %v\n", serr)
			task.Stop("failed")
			return 1
		}
		task.OnStopFunc(func() { _ = s.Close() })
		endpoint = s.Addr()
	}
	if err := runSSHShare(ctx, task, endpoint, pairingTTL, *transportFlag, *verbose, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "share: %v\n", err)
		task.Stop("failed")
		return 1
	}

	<-ctx.Done()
	fmt.Fprintf(os.Stderr, "catflap share: shutting down, destroying this machine's SSH access\n")
	task.Stop("shutdown")
	<-task.Done()
	return 0
}

// runSSHShare starts the one-shot pairing exchange for task, prints
// the pairing code, and registers the delivered client key — the SSH
// endpoint accepts no key at all until this completes.
func runSSHShare(ctx context.Context, task *sshhost.Task, endpoint string, pairingTTL time.Duration, transportName string, verbose bool, out io.Writer) error {
	remaining := time.Until(task.ExpiresAt)
	if pairingTTL > remaining {
		pairingTTL = remaining
	}
	if pairingTTL > pair.MaxCodeTTL {
		pairingTTL = pair.MaxCodeTTL
	}
	offer := pair.SSHOffer{
		Version: 1, TaskID: task.ID, Transport: transportName,
		Endpoint: endpoint, HostKey: task.HostKeyAuthorizedLine(),
		ExpiresAt: task.ExpiresAt,
	}
	stillLive := func() bool {
		select {
		case <-task.Done():
			return false
		default:
			return true
		}
	}
	//nolint:contextcheck // reason: the pair server ServeSSHOffer starts is governed by its own TTL timer and by the goroutine below (task.Done()/ctx.Done()), never by this function's own ctx parameter directly — matching issuePairCode's identical exemption in serve.go.
	pairSrv, err := pair.ServeSSHOffer(transportName, offer, pairingTTL, verbose, stillLive, func(pub string) error {
		key, _, _, _, perr := gossh.ParseAuthorizedKey([]byte(pub))
		if perr != nil {
			return perr
		}
		task.SetAllowedKey(key)
		return nil
	})
	if err != nil {
		return fmt.Errorf("start pair server: %w", err)
	}
	// A pair server must never outlive its task.
	go func() {
		select {
		case <-task.Done():
			pairSrv.Close()
		case <-ctx.Done():
			pairSrv.Close()
		}
	}()

	code, err := pair.Encode(transportName, pairSrv.Addr())
	if err != nil {
		pairSrv.Close()
		return fmt.Errorf("encode pairing code: %w", err)
	}
	_, _ = fmt.Fprintf(out, "Sharing this machine for %s\n\nPairing code:\n  %s\n\nTell Claude:\n  Connect to Catflap using %s\n\nExpires: %s\n",
		ttlDisplay(task.ExpiresAt), code, code, task.ExpiresAt.Format(time.Kitchen))
	return nil
}

func ttlDisplay(expiresAt time.Time) string {
	return time.Until(expiresAt).Round(time.Second).String()
}
