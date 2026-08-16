// Command cbomscope inventories the cryptography a project uses — in its Go
// sources and in what its endpoints actually negotiate — and writes it out as a
// CycloneDX cryptography bill of materials.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"text/tabwriter"
	"time"

	"github.com/polycratia/cbomscope/internal/asset"
	"github.com/polycratia/cbomscope/internal/cbom"
	"github.com/polycratia/cbomscope/internal/classify"
	"github.com/polycratia/cbomscope/internal/probe"
	"github.com/polycratia/cbomscope/internal/scan"
)

const usage = `cbomscope — what cryptography is in here, and how it stands against a quantum computer.

Usage:
  cbomscope scan <dir> [-json] [-fail-on <posture>]
        Read Go sources and report the cryptography they use.

  cbomscope probe <host:port> [-json]
        Handshake with a TLS endpoint and report what it negotiated.

  cbomscope cbom <dir> [-probe <host:port>] [-o <file>]
        Write a CycloneDX 1.6 cryptography bill of materials.

Postures: broken, quantum_vulnerable, quantum_reduced, hybrid, quantum_safe,
not_applicable, unknown.
By default only "broken" fails the command: it is the one that is already a
problem today, while quantum_vulnerable describes almost every deployment on
earth and would make the exit code meaningless.
`

func main() {
	err := run(os.Args[1:], os.Stdout)
	var code exitCode
	switch {
	case errors.As(err, &code):
		os.Exit(int(code))
	case err != nil:
		fmt.Fprintln(os.Stderr, "cbomscope:", err)
		os.Exit(2)
	}
}

type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(out, usage)
		return nil
	}
	switch args[0] {
	case "scan":
		return cmdScan(args[1:], out)
	case "probe":
		return cmdProbe(args[1:], out)
	case "cbom":
		return cmdCBOM(args[1:], out)
	case "help", "-h", "--help":
		fmt.Fprint(out, usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q\n\n%s", args[0], usage)
	}
}

// parseArgs parses flags that appear before, after or between the positional
// arguments. Go's flag package stops at the first non-flag word, which would
// silently swallow "cbomscope cbom . -o out.json" — the form everyone writes.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

func cmdScan(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print assets as JSON")
	failOn := fs.String("fail-on", string(asset.Broken), "posture that makes the command exit 1 (none to disable)")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("scan needs exactly one directory")
	}

	found, err := scan.Dir(positional[0])
	if err != nil {
		return err
	}
	assets := classify.ApplyAll(found)
	if *asJSON {
		if err := writeJSON(out, assets); err != nil {
			return err
		}
	} else {
		report(out, assets)
	}
	return gate(assets, *failOn)
}

func cmdProbe(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print assets as JSON")
	timeout := fs.Duration("timeout", probe.DefaultTimeout, "how long to wait for the handshake")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("probe needs exactly one host:port")
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	found, err := probe.Endpoint(ctx, positional[0])
	if err != nil {
		return err
	}
	assets := classify.ApplyAll(found)
	if *asJSON {
		return writeJSON(out, assets)
	}
	report(out, assets)
	return nil
}

func cmdCBOM(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("cbom", flag.ContinueOnError)
	endpoint := fs.String("probe", "", "also probe this host:port and include what it negotiated")
	outPath := fs.String("o", "", "write the document here instead of stdout")
	timeout := fs.Duration("timeout", probe.DefaultTimeout, "how long to wait for the handshake")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 1 {
		return fmt.Errorf("cbom needs exactly one directory")
	}

	found, err := scan.Dir(positional[0])
	if err != nil {
		return err
	}
	if *endpoint != "" {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		negotiated, err := probe.Endpoint(ctx, *endpoint)
		if err != nil {
			return err
		}
		found = append(found, negotiated...)
	}

	doc := cbom.Build(classify.ApplyAll(found), time.Now())
	body, err := doc.Encode()
	if err != nil {
		return err
	}
	if *outPath == "" {
		_, err = out.Write(body)
		return err
	}
	return os.WriteFile(*outPath, body, 0o644)
}

// order puts the postures that need a decision first.
var order = []asset.Posture{
	asset.Broken,
	asset.QuantumVulnerable,
	asset.QuantumReduced,
	asset.PostureUnknown,
	asset.Hybrid,
	asset.QuantumSafe,
	asset.NotApplicable,
}

func report(out io.Writer, assets []asset.Asset) {
	if len(assets) == 0 {
		fmt.Fprintln(out, "No cryptography found. That is a finding too: check that the path is right.")
		return
	}

	sorted := slices.Clone(assets)
	slices.SortStableFunc(sorted, func(a, b asset.Asset) int {
		return slices.Index(order, a.Posture) - slices.Index(order, b.Posture)
	})

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "POSTURE\tASSET\tWHERE\tWHY")
	for _, a := range sorted {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.Posture, a.Name, a.Location.String(), a.Rationale)
	}
	tw.Flush()

	counts := map[asset.Posture]int{}
	for _, a := range assets {
		counts[a.Posture]++
	}
	fmt.Fprintf(out, "\n%d asset(s):", len(assets))
	for _, posture := range order {
		if counts[posture] > 0 {
			fmt.Fprintf(out, " %s=%d", posture, counts[posture])
		}
	}
	fmt.Fprintln(out)
}

func gate(assets []asset.Asset, failOn string) error {
	if failOn == "" || failOn == "none" {
		return nil
	}
	if !slices.Contains(order, asset.Posture(failOn)) {
		return fmt.Errorf("-fail-on %q is not a posture; expected one of %v", failOn, order)
	}
	for _, a := range assets {
		if string(a.Posture) == failOn {
			return exitCode(1)
		}
	}
	return nil
}

func writeJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
