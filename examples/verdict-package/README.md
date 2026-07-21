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
committed inside this verdict's `verdict_hash`, so tidying a single byte would
break the anchor and the example would stop verifying. What was evaluated is
what is published.

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
$ cargo install seetrex-verifier --locked --version 0.3.1
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

**With the anchor taken from the chain export** — the way an auditor works:

```
$ seetrex-verifier verify-chain examples/verdict-package/example-audit-tenant-chain.json
Public chain package VERIFIED OFFLINE
  verdict_count:   1
  last_chain_hash: ee6879123d5b8b67267e740ca93bfba1d543892177604b9742791b84bebf5a3e

Compare these two values against the vendor's public Trust Center page for this tenant — a match proves the LINKS of the observed history are intact: no row was inserted, removed or reordered, and no hash column was altered, without breaking a link.

NOT covered by this check: the human-readable columns of each row (verdict_outcome, ruleset_id, appended_at, verdict_id). They are not inputs to the chain link, so altering them keeps every link — and the hash above — valid. Each is committed inside its own verdict_hash, which you can only recompute from that verdict's package (`verify-package`). Treat these columns as unverified metadata until you do.

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
