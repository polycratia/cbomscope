// Command cbomscope inventories the cryptography a project uses — in its Go
// sources, in the modules it depends on, and in what its endpoints actually
// negotiate — and writes it out as a CycloneDX cryptography bill of materials.
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
	"strings"
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
  cbomscope scan <dir> [-deps] [-json] [-fail-on <posture>]
        Read Go sources and report the cryptography they use.
        -deps also reads the modules go.mod requires.

  cbomscope probe <host:port> [-json]
        Handshake with a TLS endpoint and report what it negotiated,
        including whether the key exchange carried anything post-quantum.

  cbomscope cbom <dir> [-deps] [-probe <host:port>] [-o <file>]
        Write a CycloneDX 1.6 cryptography bill of materials.

  cbomscope table [-json]
        Print the classification table every verdict is read from.

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
	case "table":
		return cmdTable(args[1:], out)
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
	deps := fs.Bool("deps", false, "also read the source of the modules go.mod requires")
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
	var unread []scan.Module
	if *deps {
		dependencies, err := scan.Deps(positional[0])
		if err != nil {
			return err
		}
		found = append(found, dependencies.Assets...)
		unread = dependencies.Missing
	}

	assets := classify.ApplyAll(found)
	if *asJSON {
		if err := writeJSON(out, assets); err != nil {
			return err
		}
	} else {
		report(out, assets)
		reportUnread(out, unread)
	}
	return gate(assets, *failOn)
}

func cmdProbe(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the handshake as JSON")
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
	result, err := probe.Endpoint(ctx, positional[0])
	if err != nil {
		return err
	}
	result.Assets = classify.ApplyAll(result.Assets)
	if *asJSON {
		return writeJSON(out, result)
	}
	report(out, result.Assets)
	reportHandshake(out, result)
	return nil
}

func cmdCBOM(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("cbom", flag.ContinueOnError)
	endpoint := fs.String("probe", "", "also probe this host:port and include what it negotiated")
	deps := fs.Bool("deps", false, "also read the source of the modules go.mod requires")
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
	if *deps {
		dependencies, err := scan.Deps(positional[0])
		if err != nil {
			return err
		}
		found = append(found, dependencies.Assets...)
	}
	if *endpoint != "" {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		negotiated, err := probe.Endpoint(ctx, *endpoint)
		if err != nil {
			return err
		}
		found = append(found, negotiated.Assets...)
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

// cmdTable prints the classification table itself. A reviewer who wants to
// check a posture should not have to read the source to find out where the
// verdict came from, and a family missing from this listing is the honest shape
// of a gap.
func cmdTable(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("table", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the table as JSON")
	positional, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(positional) != 0 {
		return fmt.Errorf("table takes no arguments")
	}
	if *asJSON {
		return writeJSON(out, classify.Table)
	}

	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "FAMILY\tVERDICT\tSOURCE")
	for _, rule := range classify.Table {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", rule.Family, rule.PostureLabel(), rule.Citation)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(out, "\n%d row(s). A family with no row here is reported as unknown.\n", len(classify.Table))
	return nil
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

// reportUnread names the dependencies whose source was not on disk. Leaving
// them out silently would read exactly like having checked them.
func reportUnread(out io.Writer, modules []scan.Module) {
	if len(modules) == 0 {
		return
	}
	fmt.Fprintf(out, "\n%d module(s) required by go.mod were not read; run `go mod download` to include them:\n", len(modules))
	for _, m := range modules {
		fmt.Fprintln(out, "  "+m.Coordinate())
	}
}

// reportHandshake says what the handshake chose to exchange keys with and what
// authenticated it. The key exchange gets a line of its own because the absence
// is the finding: every asset in the list above can look individually
// reasonable while the traffic is being recorded today to be decrypted later.
func reportHandshake(out io.Writer, r probe.Result) {
	fmt.Fprintln(out)
	switch r.KeyExchange {
	case probe.KeyExchangePostQuantum:
		fmt.Fprintf(out, "Post-quantum key exchange: %s. What is recorded off this wire today does not rest on a classical assumption alone.\n", r.Group)
	case probe.KeyExchangeClassical:
		fmt.Fprintf(out, "No post-quantum key exchange: %s is classical, and %s was offered and declined. Traffic recorded today can be decrypted once a quantum computer exists.\n",
			r.Group, strings.Join(probe.OfferedPostQuantum(), ", "))
	case probe.KeyExchangeUnknown:
		fmt.Fprintf(out, "Key exchange %s is not one this tool has a name for: check the codepoint against the IANA registry rather than reading it as classical.\n", r.Group)
	default:
		fmt.Fprintln(out, "The handshake reported no key exchange group, so none of it was post-quantum.")
	}
	if r.Signature != "" {
		fmt.Fprintf(out, "Handshake signature: %s. A signature is forged at the moment it is verified rather than years afterwards, so this one is a deadline, not a leak.\n", r.Signature)
	}
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
