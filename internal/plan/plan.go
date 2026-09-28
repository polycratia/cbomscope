// Package plan orders the migration an inventory implies.
//
// An inventory says what cryptography is in use. It does not say what to do
// first, and the posture alone cannot: quantum_vulnerable describes almost every
// deployment on earth, so ranking by posture puts the RSA key in a test helper
// beside the one that signs production tokens. What separates those two is where
// the asset can be reached from and how long what it protects has to stay
// secret.
//
//	score = posture × (exposure + lifetime)
//
// Every weight is a row of Scale and carries the reason it exists; every item
// prints the arithmetic that produced it. An order a reader cannot recompute is
// an opinion, which is the thing this tool exists to replace.
package plan

import (
	"fmt"
	"slices"
	"strings"

	"github.com/polycratia/cbomscope/internal/asset"
)

// Formula is the scoring rule, written wherever a reader meets the numbers.
const Formula = "score = posture × (exposure + lifetime)"

// Factor is one weight together with the reason it carries.
type Factor struct {
	Name   string `json:"name"`
	Weight int    `json:"weight"`
	Reason string `json:"reason"`
}

// Dimension is one axis of the score, with every weight it can take.
type Dimension struct {
	Name    string   `json:"name"`
	Factors []Factor `json:"factors"`
}

var (
	brokenNow = Factor{Name: "broken", Weight: 4,
		Reason: "already broken classically: the work is overdue rather than forecast"}
	shorFalls = Factor{Name: "quantum_vulnerable", Weight: 3,
		Reason: "Shor removes the hardness assumption: the algorithm is replaced, not resized"}
	unjudged = Factor{Name: "unknown", Weight: 2,
		Reason: "nobody has judged this one yet: ranked in the middle, because an unjudged asset put last reads as a safe one"}
	resizable = Factor{Name: "quantum_reduced", Weight: 1,
		Reason: "a larger size restores the margin: a parameter change rather than a migration"}

	atEndpoint = Factor{Name: "live endpoint", Weight: 3,
		Reason: "negotiated on a live endpoint: reachable by anyone who can connect, and recordable while it is"}
	firstParty = Factor{Name: "first-party source", Weight: 2,
		Reason: "code in this repository: the change is an edit this team can make"}
	inDependency = Factor{Name: "dependency", Weight: 1,
		Reason: "code in a dependency: reached only through the code above it, and fixed by an upgrade rather than an edit"}

	keyExchange = Factor{Name: "key exchange", Weight: 3,
		Reason: "protects traffic that can be recorded today and decrypted once the assumption falls"}
	storedData = Factor{Name: "stored data", Weight: 2,
		Reason: "no deadline stated by the finding: counted as data that outlives the process which wrote it"}
	signature = Factor{Name: "signature", Weight: 1,
		Reason: "a signature is forged at the moment it is verified, not years afterwards"}
)

// Scale is every weight the score is built from. It is data so that an ordering
// can be recomputed by hand, and so that changing a judgement means changing a
// row rather than a branch.
var Scale = []Dimension{
	{Name: "posture", Factors: []Factor{brokenNow, shorFalls, unjudged, resizable}},
	{Name: "exposure", Factors: []Factor{atEndpoint, firstParty, inDependency}},
	{Name: "lifetime", Factors: []Factor{keyExchange, storedData, signature}},
}

// Item is one asset with the work it implies and the arithmetic that ranked it.
type Item struct {
	Asset    asset.Asset `json:"asset"`
	Score    int         `json:"score"`
	Posture  Factor      `json:"posture"`
	Exposure Factor      `json:"exposure"`
	Lifetime Factor      `json:"lifetime"`
}

// Arithmetic is the score written out, so the number in a column can be checked
// against the line that carries it.
func (i Item) Arithmetic() string {
	return fmt.Sprintf("%s (%d) × [%s (%d) + %s (%d)]",
		i.Posture.Name, i.Posture.Weight,
		i.Exposure.Name, i.Exposure.Weight,
		i.Lifetime.Name, i.Lifetime.Weight)
}

// Report is the ordered work, and what was examined and found to need none.
type Report struct {
	Formula string `json:"formula"`
	Items   []Item `json:"items"`
	// Settled are the assets with no migration work: post-quantum, hybrid, or
	// carrying no posture of their own. They are counted rather than dropped,
	// because a report that omits what it checked reads exactly like one that
	// never looked.
	Settled []asset.Asset `json:"settled"`
}

// Build ranks classified assets by the work they imply.
func Build(assets []asset.Asset) Report {
	report := Report{
		Formula: Formula,
		Items:   make([]Item, 0, len(assets)),
		Settled: make([]asset.Asset, 0),
	}
	for _, a := range assets {
		posture, ranked := postureFactor(a.Posture)
		if !ranked {
			report.Settled = append(report.Settled, a)
			continue
		}
		exposure, lifetime := exposureFactor(a), lifetimeFactor(a)
		report.Items = append(report.Items, Item{
			Asset:    a,
			Score:    posture.Weight * (exposure.Weight + lifetime.Weight),
			Posture:  posture,
			Exposure: exposure,
			Lifetime: lifetime,
		})
	}
	// Ties are settled by name and position so that two listings over unchanged
	// code can be diffed.
	slices.SortStableFunc(report.Items, func(a, b Item) int {
		if d := b.Score - a.Score; d != 0 {
			return d
		}
		return compareAssets(a.Asset, b.Asset)
	})
	slices.SortStableFunc(report.Settled, compareAssets)
	return report
}

// postureFactor reports the weight of a posture, and false where the posture
// implies no migration at all. Anything it does not recognise — including an
// asset that never reached the classifier — is ranked as unjudged rather than
// settled: silence is not a clean bill of health.
func postureFactor(p asset.Posture) (Factor, bool) {
	switch p {
	case asset.QuantumSafe, asset.Hybrid, asset.NotApplicable:
		return Factor{}, false
	case asset.Broken:
		return brokenNow, true
	case asset.QuantumVulnerable:
		return shorFalls, true
	case asset.QuantumReduced:
		return resizable, true
	}
	return unjudged, true
}

func exposureFactor(a asset.Asset) Factor {
	switch {
	case a.Location.Host != "":
		return atEndpoint
	case a.Module != "":
		return inDependency
	default:
		return firstParty
	}
}

func lifetimeFactor(a asset.Asset) Factor {
	switch a.Primitive {
	case asset.KEM, asset.KeyAgree, asset.PKE:
		return keyExchange
	case asset.Signature:
		return signature
	}
	return storedData
}

func compareAssets(a, b asset.Asset) int {
	if d := strings.Compare(a.Name, b.Name); d != 0 {
		return d
	}
	return strings.Compare(a.Location.String(), b.Location.String())
}
