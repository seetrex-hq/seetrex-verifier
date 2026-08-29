# Example verdict package

A complete, **fully synthetic** verdict package plus the public chain export
that anchors it. Its only purpose is to let you exercise the verifier's happy
paths before you have a real package in hand — no account, no network, no
contact with Seetrex.

Every byte here is invented: a synthetic tenant, a synthetic CycloneDX SBOM
(`example-service` with `example-lib` / `example-utils`), and a demo ruleset
that declares itself not to be a real regulatory control. There is no
operational data of any kind — no real hostname, path, address, identifier or
dependency graph.

The ruleset ships **exactly as it was evaluated**, developer prose and all —
its `doc` field still reads like the internal note it was. That is not an
oversight, it is the property being demonstrated: the ruleset's content hash is
committed inside this verdict's `verdict_hash`, so changing what the ruleset
*says* — a word of that prose, a threshold, a rule — breaks the anchor and the
example stops verifying. Re-*encoding* it does not, and that is deliberate: the
hash is taken over the canonical (JCS) form of the parsed document, so
re-indenting, reordering keys or writing the non-ASCII characters as `\uXXXX`
escapes all reach the same anchor. It is what lets you recompute this hash with
any conformant JSON library instead of ours. What was evaluated is what is
published.

```
examples/verdict-package/
├── package/                                 <- what `verify-package` consumes
│   ├── manifest.json
│   ├── verdict.json
│   ├── ruleset.json
│   └── evidence/762e8074-….json
└── example-audit-tenant-chain.json          <- the EXTERNAL anchor source
```

## The two happy paths

Install the verifier first (see the repository README or
[`docs/AUDITOR_KIT.md`](../../docs/AUDITOR_KIT.md)):

```
$ cargo install seetrex-verifier --locked --version 0.3.5
```

**Without an external anchor** — internal consistency only:

```
$ seetrex-verifier verify-package examples/verdict-package/package
...
STEP 7 external anchor SKIPPED — no --expected-verdict-hash supplied; the result is self-consistent only
SELF-CONSISTENT (unanchored)
```

Exit code `4`. This is deliberately *not* a verification: a coherent forgery is
self-consistent by construction. The package can never be its own trust root.

**With the anchor taken from the chain export** — the way an auditor works.
The transcript below was re-captured on 2026-08-29 with the `0.3.5`
executable installed by the command above, run against the files in this
directory; it is byte-identical to the `0.3.4` capture it replaces:

```
$ seetrex-verifier verify-chain examples/verdict-package/example-audit-tenant-chain.json
Public chain package VERIFIED OFFLINE
  verdict_count:   1
  last_chain_hash: ee6879123d5b8b67267e740ca93bfba1d543892177604b9742791b84bebf5a3e

Compare these two values against the vendor's public Trust Center page for this tenant. A match proves this file agrees with what the vendor publishes RIGHT NOW — nothing more. It does NOT prove rows were not removed: a vendor who republishes a truncated chain also republishes its shorter head, so both sides of this comparison move together. What catches removal is material you kept earlier — a copy of this export, or a verdict package whose verdict_hash (recompute it with `verify-package`) still appears in a row of the published chain. Each export you fetch should extend the prefix you already hold, not rewrite it; keeping and comparing that material is your step. This tool has no command for either comparison; you must keep the material and make it yourself.

NOT covered by this check: the human-readable columns of each row (verdict_outcome, ruleset_id, appended_at, verdict_id). They are not inputs to the chain link, so altering them keeps every link — and the hash above — valid. Two of them — verdict_outcome and ruleset_id — are committed inside that row's verdict_hash, recomputable only from that verdict's package (`verify-package`). The other two — appended_at and verdict_id — are committed NOWHERE: they are inputs neither to the chain link nor to verdict_hash, and no artifact we publish binds them. Treat all four as unverified metadata; the last two you cannot verify at all.

$ seetrex-verifier verify-package examples/verdict-package/package \
    --expected-verdict-hash 93bcd10fd82ae721c478130b35c2c2c9030cbe2dec02e0c495254f7cbee1af69
...
STEP 7 external anchor OK — the recomputed hash matches the externally supplied expected hash
INTEGRITY-OK (weak)
```

Exit code `0`. The anchor hash is read from the chain export — a file obtained
**outside** the package — exactly as you would read it from a vendor's public
Trust Center. In this example the chain holds a single genesis row, so its
`chain_hash` is the SHA-256 of the ASCII bytes of the `verdict_hash` alone; a
real chain links every later row to its predecessor.

The two paragraphs the chain check prints after its banner are **reproduced here
in full, and must stay that way**. The `verify-chain` banner names a strong
result, and the scope that follows is what keeps that result from being read as
more than it is: the link preimage covers only the hash columns, so an edit to
`verdict_outcome`, `ruleset_id` or `appended_at` leaves every link — and the
head hash you would compare — intact. An earlier revision of this file quoted
the banner alone. Eliding those paragraphs as boilerplate is how the overclaim
comes back.

## Try breaking it

The checks are only worth what their failures prove. Alter one byte of any file
under `package/`, or pass a wrong `--expected-verdict-hash`, and the run must
fail loudly, naming the step and the file — exit code `1`, no terminal token. If
it ever fails quietly, that is a bug worth reporting.

The chain export beside it is the documented exception, and it is worth breaking
on purpose to see the limit for yourself. Change `verdict_outcome` from
`SATISFIED` to `VIOLATED` in `example-audit-tenant-chain.json` and run
`verify-chain` again: it still prints `VERIFIED OFFLINE`, still prints the same
`last_chain_hash`, and still exits `0`. That is not a bug — those columns are
not inputs to the chain link, which is exactly what the scope paragraph above
says. It is also the reason that paragraph is printed at the same volume as the
banner: without it, this example would read as a promise the check never made.

## What this proves — and what it does not

Reproduced from the crate README, because the limit matters as much as the
guarantee:

> 1. **Record integrity — fully independent.** Using only public material, a
>    third party can verify every cryptographic quantity of a verdict package
>    with no vendor involvement at all.
> 2. **Outcome re-derivation — engine execution required.** Recomputing the
>    verdict *outcome* from the derived facts re-runs the inference engine,
>    which is not open source. It is available as a signed, reproducibly built
>    binary (black box), or as a source rebuild under NDA for regulators.

Package integrity also says nothing about *freshness or chain position* (a
genuine but superseded verdict still passes) nor about the truthfulness of the
ingested evidence. Both limits are stated in full in
[`docs/AUDITOR_KIT.md`](../../docs/AUDITOR_KIT.md) and in the byte-level format
specification, [`docs/SPEC_VERDICT_PACKAGE_V1.md`](../../docs/SPEC_VERDICT_PACKAGE_V1.md).
