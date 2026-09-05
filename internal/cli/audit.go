package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/juntaki/catflap/internal/audit"
)

// Audit implements `catflap audit <verify|anchor>`.
func Audit(args []string) int {
	if len(args) == 0 {
		fmt.Fprintf(os.Stderr, "usage: catflap audit <verify|anchor> ...\n")
		return 2
	}
	switch args[0] {
	case "verify":
		return auditVerify(args[1:])
	case "anchor":
		return auditAnchor(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown audit command %q\n", args[0])
		return 2
	}
}

func auditVerify(args []string) int {
	fs := flag.NewFlagSet("audit verify", flag.ContinueOnError)
	expectHead := fs.String("expect-head", "", "require the chain head to equal this hash")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: catflap audit verify [--expect-head H] <file>\n")
		return 2
	}
	rep, err := audit.Verify(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		return 1
	}
	fmt.Printf("valid hash chain: %d entries, task %s\n", rep.Entries, rep.Task)
	fmt.Printf("head: %s\n", rep.Head)
	if rep.HasCreate {
		fmt.Printf("create event: present\n")
	}
	if rep.Terminal != "" {
		fmt.Printf("terminal event: %s\n", rep.Terminal)
	} else {
		fmt.Printf("terminal event: none (task still live or log rotated)\n")
	}
	if *expectHead != "" && rep.Head != *expectHead {
		fmt.Fprintf(os.Stderr, "INVALID: head %s != expected %s (truncation or rewrite)\n", rep.Head, *expectHead)
		return 1
	}
	fmt.Printf("note: a valid chain is not proof against whole-file replacement; pair with an external anchor\n")
	return 0
}

func auditAnchor(args []string) int {
	fs := flag.NewFlagSet("audit anchor", flag.ContinueOnError)
	outPath := fs.String("out", "", "append the head record to this anchor log (0600) as well as printing it")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: catflap audit anchor [--out anchor.log] <file>\n")
		return 2
	}
	// Anchor only valid chains: anchoring garbage proves nothing.
	rep, err := audit.Verify(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "refusing to anchor invalid chain: %v\n", err)
		return 1
	}
	line := fmt.Sprintf("v%d %s %d %s\n", audit.AuditVersion, rep.Task, rep.Entries, rep.Head)
	fmt.Print(line)
	if *outPath != "" {
		f, err := openAnchorLog(*outPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "anchor log: %v\n", err)
			return 1
		}
		if _, err := f.WriteString(line); err != nil {
			_ = f.Close()
			fmt.Fprintf(os.Stderr, "anchor log: %v\n", err)
			return 1
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			fmt.Fprintf(os.Stderr, "anchor log: %v\n", err)
			return 1
		}
		_ = f.Close()
	}
	fmt.Fprintf(os.Stderr, "keep this head outside the audit file; later: catflap audit verify --expect-head %s <file>\n", rep.Head)
	return 0
}
