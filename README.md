# cbomscope

What cryptography is in here, and how it stands against a quantum computer.

Every post-quantum migration plan starts at the same place: an inventory. You
cannot migrate what you cannot see, and most teams cannot see it — the key sizes
live in code written years ago, and the algorithms that actually protect traffic
are chosen by a TLS handshake nobody has looked at.

cbomscope reads both sides and writes the answer as a CycloneDX 1.6 cryptography
bill of materials.

## Two sources, because they disagree

```console
$ cbomscope scan .
POSTURE          ASSET    WHERE                      WHY
quantum_reduced  SHA-256  internal/cbom/cbom.go:137  256-bit digest: quantum collision search reduces the margin; SHA-384 or larger is the usual answer

1 asset(s): quantum_reduced=1
```

```console
$ cbomscope probe cloudflare.com:443
POSTURE             ASSET                   WHERE               WHY
quantum_vulnerable  ECDSA-P-256             cloudflare.com:443  Shor's algorithm solves the underlying elliptic-curve discrete logarithm
quantum_vulnerable  ECDSA-SHA256            cloudflare.com:443  Shor's algorithm solves the underlying elliptic-curve discrete logarithm
quantum_reduced     TLS_AES_128_GCM_SHA256  cloudflare.com:443  Grover halves this to about 64 bits of quantum work; 256-bit keys are the usual answer
hybrid              X25519MLKEM768          cloudflare.com:443  classical and post-quantum key exchange combined: secure if either half holds
not_applicable      TLS 1.3                 cloudflare.com:443  a protocol version has no quantum posture of its own: see the key exchange and cipher it negotiated

5 asset(s): quantum_vulnerable=2 quantum_reduced=1 hybrid=1 not_applicable=1
```

That second transcript is the reason the probe exists: source code cannot tell
you that this deployment has already moved its key exchange to a hybrid
post-quantum group, because no source in the repository chose it.

```bash
cbomscope cbom . -probe api.example.com:443 -o cbom.json
```

## What it reads, and what it will not guess

The scanner reads Go syntax trees, not text. An import alias is followed; a
comment or a string that mentions `rsa.GenerateKey` is not a finding. Parameters
are taken from the call where they are literal — `rsa.GenerateKey(rand.Reader,
2048)` becomes RSA-2048 — and where the size arrives in a variable, the asset is
reported with **no size at all** rather than a plausible default. AES-128 and
AES-256 do not share a verdict, so pretending to know which one it is would be
the one unforgivable answer.

The probe skips certificate verification on purpose: the job is to see what an
endpoint presents, and an expired or self-signed certificate is exactly the
inventory that needs attention. The connection carries no data.

## The postures

| Posture | Meaning |
|---|---|
| `broken` | already broken classically — MD5, SHA-1, RC4, 3DES, TLS 1.0/1.1 |
| `quantum_vulnerable` | Shor's algorithm removes the hardness assumption — RSA, DSA, DH, everything elliptic-curve |
| `quantum_reduced` | Grover halves the effective strength — AES-128, SHA-256 |
| `hybrid` | classical and post-quantum combined; holds if either half holds |
| `quantum_safe` | AES-256, SHA-384 and larger, ML-KEM, ML-DSA, SLH-DSA |
| `not_applicable` | carries no posture of its own — a protocol version |
| `unknown` | found, but not enough is known to judge it |

Only `broken` fails the command by default. `quantum_vulnerable` describes
almost every deployment on earth right now; making it an error would turn the
exit code into noise on the first run and get the tool removed from CI. Use
`-fail-on` to choose a different gate.

None of this predicts when a cryptographically relevant quantum computer
arrives. It says what would fall if one did.

## Where a verdict comes from

Every verdict is a row in one table — `internal/classify/table.go` — and every
row names the document it was read from. The citation travels with the finding,
into `-json` output and into the CBOM as a `cbomscope:citation` property, so a
reviewer can check a posture against FIPS 203 or RFC 8996 instead of trusting
the tool.

| Family | Verdict | Source |
|---|---|---|
| RSA, DSA, DH, ECDSA, ECDH, Ed25519, X25519 | `quantum_vulnerable` | Shor 1997; NIST IR 8547 |
| AES, ChaCha20, HMAC | by key size | Grover 1996; NIST IR 8547 |
| SHA-2, SHA-3 | by digest size | Brassard, Hoyer and Tapp 1998 |
| ML-KEM / Kyber, ML-DSA / Dilithium, SLH-DSA | `quantum_safe` | FIPS 203, 204, 205 |
| LMS, XMSS | `quantum_safe` | SP 800-208 |
| MD5, SHA-1, RC4, DES, 3DES | `broken` | RFC 6151, SHAttered, RFC 7465, SP 800-131A, Sweet32 |
| SSL, TLS 1.0/1.1 | `broken` | RFC 7568, RFC 8996 |
| TLS 1.2/1.3 | `not_applicable` | RFC 5246, RFC 8446 |
| X25519MLKEM768 and other hybrid groups | `hybrid` | draft-ietf-tls-hybrid-design |

A family with no row is reported as `unknown`, with a rationale saying a person
has to judge it, and with no citation attached — a source printed beside an
answer nobody has would make the gap look checked. Keeping this as data rather
than as a chain of conditions is the point: the gaps are visible, and closing
one is a row.

## Install

```bash
go install github.com/polycratia/cbomscope/cmd/cbomscope@latest
```

Go 1.25 or newer — the probe reports the negotiated key exchange group, which
needs that version. No dependencies outside the standard library.

## Status

Early, and narrower than it will be. What exists works end to end; the gaps are
listed rather than implied.

| | |
|---|---|
| Source scanning | Go only — the standard library's crypto packages, `x/crypto/chacha20poly1305`, `crypto/mlkem` |
| Live probing | TLS: version, cipher suite, key exchange group, certificate key and signature |
| Output | CycloneDX 1.6 cryptographic assets; the posture and its citation travel as `cbomscope:` properties, since the spec has no field for them |
| Not yet | other languages, certificate and key files on disk, container images, config files, JOSE/JWT algorithms, SSH |

## Alongside CBOMkit

[CBOMkit](https://github.com/cbomkit) (originally IBM, now under the
Post-Quantum Cryptography Alliance) covers more ground: it scans Java and Python
sources, inspects container images and filesystems, and ships a web service for
viewing the results. If that is the shape you need, use it.

cbomscope overlaps deliberately little. It scans Go sources, which CBOMkit does
not, and it probes live endpoints, which none of that toolchain does — a
handshake is the only place an inventory can see a hybrid key exchange already
in production. It is one static binary with no server and no database.

## Development

```bash
make test   # go vet + go test ./...
make demo   # scan this repository and write a CBOM
```

The probe is tested against a TLS server started inside the test process, so the
suite needs no network.

## License

MIT

Made by [polycratia](https://polycratia.com).
