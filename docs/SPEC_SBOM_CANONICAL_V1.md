# Seetrex Compliance -- Canonical SBOM Projection Specification

> **Status: v1.0-draft -- specifies the `lockfile-v1` projection; pending adversarial
> review. This is the contract an implementation must meet, not a description of any
> one implementation. A reference implementation now exists (`crates/verifier/src/sbom/`),
> and the normative vector of Section 6.2, the negative controls of 6.3, the key list of
> 5.1 and the property literals of 5.4 are re-derived from it on every test run -- so this
> document and that code cannot drift apart in silence. That implementation is shipped
> in `seetrex-verifier` 0.3.4 (2026-08-27): the `emit-sbom` and `verify-sbom`
> subcommands this document specifies are part of that published release, so an
> auditor who installs `--version 0.3.4` from crates.io obtains them. The earlier
> `0.3.3` binary does not carry them.**

**Spec version:** 1 (draft) - **Projection id:** `lockfile-v1` - **Emitted document:**
CycloneDX `1.5`, JSON

---

## 1. Purpose and scope

This document specifies, at byte level, a **pure projection from a dependency lockfile
to a CycloneDX 1.5 document**, so that an independent party -- an auditor, a customer, a
regulator -- can take the published lockfile and the published SBOM and decide **by
themselves, offline, with no vendor software**, whether the second is the faithful
projection of the first.

What makes that possible is byte determinism: the projection is a function of the
lockfile bytes and one supplied subject identifier, and of nothing else -- no clock, no
random identifier, no host state, no network. Two conforming implementations, on two
machines, in two languages, produce the **same bytes** and therefore the same SHA-256.
SHA-256, a JSON parser and an RFC 8785 (JSON Canonicalization Scheme, "JCS") serializer
are sufficient; the Cargo ecosystem additionally needs a TOML parser.

### 1.1 Requirements language

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as
described in RFC 2119 and RFC 8174 when, and only when, they appear in all capitals.

### 1.2 Non-goals

This is **not** a general-purpose SBOM generator and a conforming implementation MUST
NOT present it as one.

- **Not a metadata collector.** Licences, authors, suppliers, descriptions, homepages,
  external references and copyright are never emitted (Section 2.4). What is emitted is
  identity, and only identity.
- **Not a resolver.** It reads resolved lockfiles: it never resolves version
  constraints, walks a registry, or applies an ecosystem's directory resolution
  algorithm.
- **Not a replacement for third-party SBOM tooling.** Documents produced by other tools
  are **ingested canonicalised, never rewritten and never replaced**: an independent
  tool disagreeing with this projection is a signal, and overwriting its output would
  destroy that signal. What this document adds is the ability to **compare** such a
  document against the lockfile and report where the two differ (Section 7.4).
- **Not a full dependency graph.** The emitted graph has depth 1 by decision
  (Section 4) -- the literal minimum of Regulation (EU) 2024/2847 Annex I Part II (1),
  "a software bill of materials, covering at the very least the top-level dependencies
  of the products". *Of the products*: a workspace crate the product links is one of
  them, and Section 4.2 subtracts only the subject itself.
- **Not a proof about a running system.** The optional binary leg (Section 7.5) says
  what a given *file* was built from, not what a server is executing.

---

## 2. Inputs

| Input | Required | Meaning |
|---|---|---|
| lockfile | yes | the resolved dependency lockfile (Sections 2.1-2.3) |
| manifest | composer only | the root manifest, source of the top-level set |
| subject | yes | a purl (Section 3) naming the artefact the SBOM is about |

The subject is an **input, never a value read from an SBOM under test** (Section 7.2).
Implementations MUST NOT infer it from the lockfile: a workspace lockfile holds several
member packages and none is marked "the product", so inferring would be inventing.

The subject MUST be validated against the **same grammar of Section 3** that governs the
purls the implementation builds, and rejected as an auditor-side error (Section 7.6)
when it does not match: its type is one of `cargo`, `composer`, `npm`, it carries the
segment count of that type, every segment and the version are purl tokens, and the only
escape admitted anywhere is the `%40` of an npm scope. It is the one string in the
document a human types, and it is copied verbatim into `metadata.component`, into the
single `dependencies[].ref`, and into any error message that quotes it; a laxer reading
puts a space, an unencoded `@`, a `../`, a JSON metacharacter or the reserved token of
Section 7.7 inside an artefact whose entire value is that a stranger re-derives it.

### 2.1 Cargo -- `Cargo.lock`, `version = 3` or `version = 4`

Read: the top-level scalar `version`; each `[[package]]` entry, and within it `name`,
`version`, `source`, `checksum` (basic strings) and `dependencies` (array of strings).
`[metadata]` is ignored by name. Any other TOML construction MUST fail loud as
`UnsupportedLockShape` rather than be skipped. A top-level `version` other than `3` or
`4` MUST be rejected.

The `version` key is a **label**, and two further rules read the **shape**, so that
relabelling a format 1 or 2 file as a `3` buys nothing:

- a `checksum ...` key inside the `[metadata]` table MUST be rejected as
  `UnsupportedLockShape`. That table is ignored by name, so a digest recorded there is a
  digest the projection does not read, and the document it would publish carries no
  `hashes` at all for the packages listed in it.
- a `[[package]]` with a `source` key and **no** `checksum` MUST be rejected as
  `UnsupportedLockShape`, naming the package -- **except** for the source schemes cargo
  resolves without recording a digest, `git+` and `path+` (a git checkout is identified
  by the revision inside its own source string; a path dependency distributes no
  artifact to digest). Cargo writes the digest of everything it fetches, so a resolved
  entry without one is the format 1 or 2 shape whatever the file declares.

Dependency entries carry one, two or three whitespace-separated tokens: `"name"`,
`"name version"`, `"name version (source)"`. All three MUST be accepted. A single-token
entry whose name resolves to more than one package in the lockfile is ambiguous: the
projection MUST fail with `AmbiguousDependencyRef` and MUST NOT guess (for instance by
taking the highest version).

### 2.2 Composer -- `composer.lock` + `composer.json`

From `composer.lock`: the arrays `packages` and `packages-dev`, and within each entry
only `name` and `version`. From `composer.json`: the key sets of `require` and
`require-dev`.

The lockfile does **not** contain the root requirements, so the manifest is a second
**mandatory** input. A composer projection without it MUST fail (`MalformedManifest`)
and MUST NOT emit an empty top-level set: an empty `dependsOn` is the exact signature of
"satisfies Annex I on paper while covering nothing", and producing it by omission is
forbidden.

### 2.3 npm -- `package-lock.json`, `lockfileVersion` 2 or 3

Read: the `packages` object -- per entry, the entry key (its path) and the `version`,
`dev` and `link` fields; for the root entry (key `""`), also the key sets of
`dependencies`, `devDependencies`, `optionalDependencies` and `peerDependencies`.

- A document with a legacy top-level `dependencies` block and **no** `packages` object
  (lockfileVersion 1) MUST be rejected as `UnsupportedLockShape`.
- In lockfileVersion 2, where both representations exist, `packages` is authoritative
  and the legacy block MUST be ignored.
- Entries with `"link": true` point elsewhere in the tree and are not installed
  packages: they MUST be omitted from `components` and from the top-level set, and the
  number omitted MUST be reported in `seetrex:sbom.links_omitted` (Section 5.4) so the
  omission is visible rather than mute. A **root requirement** satisfied by such an
  entry is likewise omitted from the top-level set and MUST NOT fail: there is no
  component to point an edge at, so emitting one would leave a `dependsOn` naming a
  `bom-ref` the document never declares, and failing would make every tree that links a
  local package unprojectable. It is already counted by the same property.
- npm writes such a link in **two halves**: the `node_modules/<name>` entry carrying
  `"link": true`, and a full entry under the path that entry `resolved` to
  (`workspaces/<name>` for a workspace member). The second half MUST be **skipped** --
  as the target of a link the projection already omitted, identified by **membership in
  the set of `resolved` values** and never by a prefix or a glob -- and MUST NOT be
  counted a second time: one link is one omission, however many keys npm spends
  recording it. Without this admission a lockfile npm actually produces is rejected
  outright by the workspace rule below, which makes the whole `link` rule above
  unreachable in practice.
- Per-entry `dependencies` maps hold **constraints**, not resolved versions, and MUST
  NOT be read (Section 4.1 explains why).
- **npm workspaces are a non-goal of version 1.** A `packages` key with no
  `node_modules/` segment is a workspace path, not an installed package, and MUST be
  rejected as `UnsupportedLockShape` -- unless it is the link target admitted just
  above. Projecting one would mean deciding which member is
  "the product" -- the same invention Section 2 forbids for the subject -- and mapping
  the root's own `workspaces` globs onto lockfile keys, which is resolution rather than
  projection. A conforming v1 implementation therefore does not read workspace
  lockfiles at all; it does not read them *partially*, which is the outcome this clause
  exists to forbid.

### 2.4 Fields read and then deliberately discarded

Emitted component keys are exactly those of Section 5.2. Everything else is discarded,
and the reasons are normative, not editorial:

| Discarded | Reason |
|---|---|
| `licenses` (composer) | declarative metadata, not identity; introduces licence-expression strings whose canonical form this document does not specify |
| `author`, `authors`, `supplier`, `publisher`, `description`, `homepage`, `externalReferences`, `copyright` | provenance and, for maintainer names and addresses, **personal data**. A per-field blocklist has already leaked an `author` into a hashed canonical payload once in this product's history; this document uses an allowlist so the failure mode cannot recur |
| `integrity` (npm, `sha512-<base64>`) | covers the registry tarball, not the component identity, and not an artefact the auditor holds; base64-to-hex would be a transformation with judgement in it |
| `dist.shasum` (composer) | a SHA-1 of a zipball the registry builds on demand, not of an artefact the auditor holds -- and empty on every entry of this repository's own `composer.lock` |
| `dist.reference` (composer) | a git commit id, not a hash of the distributed artefact |
| `cpe`, `swid` | not derivable from any lockfile |
| npm per-entry `dependencies`, `engines`, `funding`, `os`, `cpu` | constraints and platform metadata, not identity |
| Cargo `[metadata]`, `[patch]`, and `source` other than as a member discriminator | not identity |

Cargo `checksum` is the single exception in the other direction, and the ONLY digest
this specification publishes: it is already a lowercase-hex SHA-256 of the crate file,
so it is emitted verbatim, with no transformation and no choice (Section 5.2). A
composer or npm document therefore carries **no `hashes` key at all**.

---

## 3. Component identity: the purl

The **package URL (purl)** is the identity of a component: deduplication key, sort key,
and the value carried by `dependencies[].ref` (Section 4.3). A name is never an identity
-- one Cargo lockfile in this product resolves 31 distinct names at more than one
version.

Grammar per ecosystem, following the purl specification's type definitions (`cargo`,
`composer`, `npm`):

| Ecosystem | Form | Notes |
|---|---|---|
| cargo | `pkg:cargo/<name>@<version>` | no namespace, no qualifiers; the `cargo` type's default repository is crates.io |
| composer | `pkg:composer/<vendor>/<name>@<version>` | a composer package name is already `vendor/name`; both segments are **lowercased**, as the purl specification requires for the `composer` type and as composer itself normalises package names. The `version` is not folded (rule 1), and the `name`/`group` keys of the component object keep the lockfile's own spelling (Section 5.2): what is normalised is the identity, not the display |
| npm, unscoped | `pkg:npm/<name>@<version>` | |
| npm, scoped | `pkg:npm/%40<scope>/<name>@<version>` | the `@` introducing the scope is percent-encoded as `%40`; the `@` separating the version is **not** |

1. **The version is the lockfile's, verbatim, and mandatory.** No normalisation of any
   kind: a composer version recorded as `v1.2.3` is emitted as `v1.2.3`. A component
   whose version cannot be read is a fail-loud `MissingVersion`, never a component
   emitted without a `version` -- a lockfile is resolved by definition, so a missing
   version means a corrupt input or a broken parser, and a BOM that looks complete while
   being incomplete is the worst available failure here.
2. **The purl is the `bom-ref`**: content-derived, therefore deterministic by
   construction, and written out as an explicit `bom-ref` key on every component and on
   `metadata.component` (Section 5.3).
3. **Deduplication is by exact purl.** Same purl and same payload collapse to one
   component; same purl and a **different** payload MUST fail with `PurlCollision`.
   Silent collapse is forbidden: in a document whose identity is the purl, two
   components sharing one purl are two objects claiming one identity.

   `scope` is the one field that is **not** part of that payload. An installed npm tree
   reaches one package at one version by several paths
   (`node_modules/a/node_modules/x` and `node_modules/b/node_modules/x`) and those
   entries routinely disagree about `dev`. They are ONE component, and the surviving
   scope is the **more permissive** one: `required` beats `optional`, because the
   artefact does ship in the product if any path needs it at runtime. Taking the last
   entry read would make the scope depend on map iteration order, and taking `optional`
   would state, inside the document, that a package which ships does not. Every other
   disagreement under one purl remains `PurlCollision`.
4. Ordering and equality of purls are over **UTF-8 bytes**, never a locale collation.

---

## 4. The dependency graph

### 4.1 Depth 1: root plus top-level, nothing else

The graph is a single entry: the subject and the purls it depends on directly.
Components do not declare their own `dependsOn`.

A transitive graph is not merely expensive, it is **not derivable**: npm lockfiles of
version 2 and 3 record per-entry dependencies as constraints, and turning those into
edges means re-implementing the ecosystem's resolution algorithm -- the result would no
longer be checkable by reading the lockfile, which is the whole point. A full graph for
one ecosystem and a shallow one for another would be worse still: two meanings under one
field name.

Depth 1 is the literal minimum of Annex I Part II (1) of Regulation (EU) 2024/2847,
which requires "a software bill of materials, covering at the very least the top-level
dependencies of the products". Where a rule below over-approximates the top-level set it
over-approximates **upwards**, the safe direction for a requirement worded "at the very
least". For cargo that over-approximation has TWO sources, both named in 4.2: the
lockfile merges normal, dev and build dependencies into one list, and the set is the
**union over every workspace member**, not the list of the member the subject names.
Nothing is subtracted from it except the subject itself, so the emitted set is a
superset of the subject's runtime top level and not a subset of it.

### 4.2 Deriving the top-level set

| Ecosystem | Source | Rule | Declared limitation |
|---|---|---|---|
| cargo | the lockfile alone | union of the `dependencies` lists of every package **without** a `source` key (the workspace members), minus the **subject** alone | the union is taken ACROSS MEMBERS, and a Cargo lockfile also merges normal, dev and build dependencies into one list, so the set **over-approximates** the runtime top level of the subject on both axes |
| composer | the manifest | key set of `require` union `require-dev`, excluding platform requirements: `php`, `php-*`, `ext-*`, `lib-*`, and any key beginning `composer` | needs the manifest as a second input (Section 2.2) |
| npm | the lockfile alone | key set of `dependencies` union `devDependencies` union `optionalDependencies` union `peerDependencies` of the root entry (`""`) | none |

Each key is mapped to the purl of the lockfile entry that resolves it; a key with no
resolving entry MUST fail loud, never be silently dropped. For composer the match is
made on the **ASCII-lowercased** name on both sides, because composer normalises package
names to lowercase: `Acme/Widget` in a manifest and `acme/widget` in the lockfile are one
package, and the purl emitted is the lockfile's spelling, which is the resolved one.

**Platform requirements are not components.** A PHP runtime or extension has no package
purl; emitting `pkg:composer/php@^8.3` would invent a component that exists in no
registry. They are excluded from the top-level set and the number excluded is reported
in a document property (Section 5.4), so the exclusion is visible rather than mute.

**The cargo rule is a union ACROSS MEMBERS, not the subject's own dependency list.**
Every package without a `source` key is a workspace member, and the lists of all of them
are merged into one set. A crate that only one member requires -- a criterion needed by
`seetrex-core` alone, say -- therefore appears in the `dependsOn` of a subject naming
`compliance`. Together with the dev/build merge this makes the emitted set a strict
**superset** of the runtime top level of the subject.

**Nothing else is subtracted, and in particular no workspace member is.** The subject
itself is removed because an edge from the root of the graph to itself is a self-loop;
every OTHER member a member depends on stays in the set. Annex I Part II (1) of
Regulation (EU) 2024/2847 requires an SBOM "covering at the very least the top-level
dependencies **of the products**", and a workspace crate the product links is a
top-level dependency of that product -- the more so when it is a closed component an
auditor cannot read for themselves. Subtracting members made the emitted set a **subset**
of the runtime top level while this section claimed a superset: measured on a published
artefact, `compliance` depends directly on `seetrex-core` and `seetrex-verifier` and
named neither under `dependsOn`. Such a member is already in `components` (Section 5.2),
so the edge resolves against a declared `bom-ref`.

That direction is deliberate and it settles what the document does and does not claim.
The CRA sentence, "covering at the very least the top-level dependencies", is **covered**
by a superset. The positive claim "every purl in `dependsOn` is a top-level dependency of
the product" is **NOT made by this document**, and no reader may derive it: in this
product's own composer projection, 7 of the 10 entries come from `require-dev`.

The limitation travels **inside** the document, in `seetrex:sbom.top_level_basis`, not
only in this prose. The cargo literal `cargo-lock-workspace-members-merged-dev` names
both halves of it -- `workspace-members` for the cross-member union, `merged-dev` for the
dev/build merge -- so an auditor comparing against a runtime-only listing of one crate
will see more entries than expected, and the document itself says why.

### 4.3 Shape

```json
"dependencies": [
  { "dependsOn": ["<purl>", "<purl>"], "ref": "<subject-purl>" }
]
```

Exactly one element. `dependsOn` is sorted ascending by purl over UTF-8 bytes and
carries no duplicates. An empty `dependsOn` is reachable only from a lockfile that
genuinely declares no dependency, never from a missing input (Section 2.2).

---

## 5. Document shape

### 5.1 Allowed top-level keys

Exactly seven, all mandatory: `bomFormat` (`"CycloneDX"`), `components`, `dependencies`,
`metadata`, `properties`, `specVersion` (`"1.5"`), `version` (the JSON integer `1`).

**No other top-level key is permitted.** In particular there is **no `serialNumber` and
no `metadata.timestamp`**, and `metadata` carries exactly one key, `component`. Both
omissions are load-bearing: either one makes two emissions of the same lockfile differ,
falsifying the premise of this specification. A content-derived `serialNumber` is not a
repair -- it would be part of the document whose hash defines it.

`specVersion` is `1.5` rather than a later revision because every other SBOM producer in
this product emits 1.5 and the ingest path passes `specVersion` through unchanged; two
spec versions in one evidence chain would be bought for nothing, since `dependencies`
and `properties` both exist in 1.5.

### 5.2 `components`

An array sorted ascending by `purl` over UTF-8 bytes -- a **total** order, since the
purl carries the version and two entries never tie. Every lockfile package entry **other
than the subject** contributes exactly one element. Permitted keys, all others
forbidden:

| Key | Emitted when | Value |
|---|---|---|
| `bom-ref` | always | the component's own purl, verbatim (Section 5.3) |
| `type` | always | the constant `"library"` |
| `name` | always | cargo: the package name; composer: the segment after `/`; npm: everything after the **last** `node_modules/` in the entry path, minus a leading scope segment |
| `group` | composer, and scoped npm | composer: the vendor; npm: the scope without its leading `@`; absent for cargo |
| `version` | always | Section 3, rule 1 |
| `purl` | always | Section 3 |
| `scope` | composer and npm | `"required"`, or `"optional"` for a composer `packages-dev` entry or an npm entry with `"dev": true`; **absent for cargo**, whose lockfile does not distinguish |
| `hashes` | **cargo only**, when the entry has a `checksum`; MUST be absent from every composer and npm component | `[{"alg":"SHA-256","content":"<the checksum verbatim>"}]`. `SHA-256` is the only `alg` label this specification admits: composer `dist.shasum` and npm `integrity` are discarded (2.4), so no other algorithm can appear |

A nested npm entry (`node_modules/a/node_modules/b`) is its own component with its own
version; collapsing it into the outer package loses a distinct resolved version and is
forbidden. Two entries that resolve to the *same* purl are, on the contrary, one
component, whose `scope` is the more permissive of the two (Section 3, rule 3) -- that
case is a repeat of one identity, not two identities under one reference.

### 5.3 `bom-ref`: written explicitly, equal to the purl

Every component, and `metadata.component`, MUST carry a `bom-ref` key whose value is
byte-identical to that object's own `purl`. `dependencies[].ref` and `dependsOn` carry
the same strings, so every reference in the document resolves against a **declared**
`bom-ref`, as strict CycloneDX 1.5 consumers require. A document whose single `ref` did
not resolve would be invalid for exactly the auditors this specification exists to
serve.

Writing the identifier costs nothing in determinism: the purl is derived from the
lockfile (Section 3), so the `bom-ref` is too. It is never a counter, a UUID, or an
index into the array -- all three would make two emissions of one lockfile differ, or
make a reference depend on position.

*On ingestion.* When such a document is ingested into this product's evidence chain, the
normaliser retains a closed set of substantive component fields and `bom-ref` is not
among them, so it is dropped -- **deterministically, for every document alike**. That is
a property of the chain's canonical form, not of this format: the canonical SBOM is a
public artefact whose contract is verified by `verify-sbom` against the lockfile
(Section 7), not by the chain normaliser. The two never disagree about the published
bytes, because only one of them defines them.

### 5.4 `properties`, and their explicitly non-load-bearing status

An array at the **BOM level** (not per component), sorted ascending by `name`:

| Name | Value |
|---|---|
| `seetrex:sbom.projection` | `lockfile-v1` |
| `seetrex:sbom.lockfile_kind` | `cargo`, `composer` or `npm` |
| `seetrex:sbom.top_level_basis` | one of `cargo-lock-workspace-members-merged-dev`, `composer-json-require-merged-dev`, `npm-lock-root-dependencies-merged-dev` |
| `seetrex:sbom.platform_requirements_excluded` | composer only: the number of platform requirements excluded from the top-level set (Section 4.2), as a decimal string with no leading zeros |
| `seetrex:sbom.links_omitted` | npm only: the number of `"link": true` entries omitted (Section 2.3), as a decimal string with no leading zeros |

The first three are emitted always; the last two are emitted for their own ecosystem
only, and are emitted even when the count is `"0"` -- an absent property and a count of
zero are different claims, and only one of them is checkable.

1. **They are not load-bearing.** No regulatory signal and no consumer rule may be
   derived from them. The top-level set lives in the **standard** `dependencies` field
   rather than in a property of this vendor's own, so that any CycloneDX consumer reads
   it without knowing the `seetrex:` prefix -- and so that it will survive this
   product's own ingest once that whitelist is widened, which is a pinned-ruleset change
   with its own gate and not an edit to this document. It does not survive it **today**:
   the normaliser keeps four keys (`bomFormat`, `specVersion`, `metadata.component`,
   `components`) and `dependencies` is not among them, so the top-level set reaches no
   content hash of the chain either, exactly like the properties of this section. What
   reaches the auditor today is the canonical FILE, whose `sha256` is its canonical hash
   and which `verify-sbom` confronts with the lockfile (Section 7) OUTSIDE the chain.
2. **They reach no content hash today.** This product's ingest normaliser discards
   BOM-level keys other than `bomFormat`, `specVersion`, `metadata.component` and
   `components`, and `properties` is not a substantive component field either. They
   exist as bytes of the published file and as self-description for a reader.
3. **The `seetrex` prefix is de facto, not registered** in the CycloneDX property
   taxonomy. Registration is a public act carrying a stability obligation and is out of
   scope here; claiming it before it happened would be false.

### 5.5 `metadata.component`: the subject

Derived from the supplied subject purl and from nothing else. Exactly five keys, for
every subject alike -- `bom-ref` (the subject purl, Section 5.3), `type` (the constant
`"application"`), `name`, `purl`, `version` -- where `name` and `version` come from
inverting the grammar of Section 3.

**No `group`, not even for a namespaced subject.** The namespace is already carried,
verbatim and in its purl-encoded form, inside `purl` and `bom-ref`; decoding it back out
into a separate key is a *transformation*, and Section 1.2 forbids this projection from
transforming its input. A composer or scoped-npm subject therefore carries the same five
keys as a cargo one, so a consumer reading `metadata.component` never has to branch on
the ecosystem. This differs from `components` (Section 5.2), where `group` is READ from
the lockfile rather than decoded out of a string the caller supplied.

The subject purl's type MUST match the lockfile kind, and BOTH `emit-sbom` and
`verify-sbom` MUST refuse a mismatch as an auditor-side error (7.6, exit code `2`):
`--kind cargo` beside a `pkg:npm/...` subject otherwise emits a perfectly canonical
document whose `metadata.component` claims an ecosystem its own components do not belong
to.

The subject does not also appear in `components`: it is one artefact with one identity,
and listing it twice would put the same purl -- the same entry in the reference space --
on two objects.

---

## 6. Canonical bytes

### 6.1 The rule

1. The document is serialised with **JCS, RFC 8785**: members sorted by the UTF-16 code
   units of their names, no insignificant whitespace, minimal string escaping, numbers
   in the ECMAScript shortest round-trip form, output encoded as UTF-8.
2. The emitted file is **exactly those bytes**: a single line, **no trailing newline**,
   UTF-8 with **no byte-order mark**.
3. JCS does not touch array order, so this document fixes it: `components` by purl
   (5.2), `dependsOn` by purl (4.3), `properties` by name (5.4).
4. The only JSON number in the document is `"version": 1`, and it MUST be an integer,
   never `1.0`.

The consequence is the property this specification exists to provide:

```
sha256(bytes of the published file) == sha256(JCS(document))
```

so an auditor checks a publication with `sha256sum` and a text editor, with no software
from this vendor involved.

### 6.2 Reference vector (NORMATIVE)

The lockfile below, its projection and that projection's SHA-256 are **normative**.
Given this lockfile and the subject `pkg:cargo/demo-app@0.2.0`, a conforming
implementation MUST produce these exact bytes and this exact hash. An implementation
that does not is non-conforming, whatever else it does.

The lockfile (706 bytes, LF line endings, one trailing newline;
`sha256 = 1708296171969c3092bef8c1224564ec4e963869a45c342ee7149994264c9d3e`):

<!-- BEGIN SBOM-REFERENCE-LOCKFILE -->
```toml
version = 4

[[package]]
name = "demo-app"
version = "0.2.0"
dependencies = [
 "leaf 0.2.0",
 "midlib",
]

[[package]]
name = "leaf"
version = "0.1.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

[[package]]
name = "leaf"
version = "0.2.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"

[[package]]
name = "midlib"
version = "0.3.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
checksum = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
dependencies = [
 "leaf 0.1.0",
]
```
<!-- END SBOM-REFERENCE-LOCKFILE -->

What this vector forces the implementation to decide: `demo-app` has no `source`, so it
is the workspace member and the top-level basis; `midlib` is referenced by the one-token
form and `leaf` by the two-token form, because `leaf` resolves at two versions and would
otherwise be ambiguous (2.1); `leaf` appearing twice is three components, not two, and
only two of the three are top-level; the edge from `midlib` to `leaf 0.1.0` is read to
resolve nothing and emitted nowhere (4.1).

The canonical projection (1223 bytes, one line, no trailing newline):

<!-- BEGIN SBOM-REFERENCE-CANONICAL -->
```
{"bomFormat":"CycloneDX","components":[{"bom-ref":"pkg:cargo/leaf@0.1.0","hashes":[{"alg":"SHA-256","content":"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"}],"name":"leaf","purl":"pkg:cargo/leaf@0.1.0","type":"library","version":"0.1.0"},{"bom-ref":"pkg:cargo/leaf@0.2.0","hashes":[{"alg":"SHA-256","content":"b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"}],"name":"leaf","purl":"pkg:cargo/leaf@0.2.0","type":"library","version":"0.2.0"},{"bom-ref":"pkg:cargo/midlib@0.3.0","hashes":[{"alg":"SHA-256","content":"c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"}],"name":"midlib","purl":"pkg:cargo/midlib@0.3.0","type":"library","version":"0.3.0"}],"dependencies":[{"dependsOn":["pkg:cargo/leaf@0.2.0","pkg:cargo/midlib@0.3.0"],"ref":"pkg:cargo/demo-app@0.2.0"}],"metadata":{"component":{"bom-ref":"pkg:cargo/demo-app@0.2.0","name":"demo-app","purl":"pkg:cargo/demo-app@0.2.0","type":"application","version":"0.2.0"}},"properties":[{"name":"seetrex:sbom.lockfile_kind","value":"cargo"},{"name":"seetrex:sbom.projection","value":"lockfile-v1"},{"name":"seetrex:sbom.top_level_basis","value":"cargo-lock-workspace-members-merged-dev"}],"specVersion":"1.5","version":1}
```
<!-- END SBOM-REFERENCE-CANONICAL -->

<!-- BEGIN SBOM-REFERENCE-SHA256 -->
```
sha256 = cb04cb0586a92e5adf1da40f37a5cc121bdd60bb4dc1b1915f5143d3d4b644dd
```
<!-- END SBOM-REFERENCE-SHA256 -->

### 6.3 Negative controls

Two deliberately wrong hashes, each isolating one mistake, so an implementer can
identify *which* mistake they made from the value alone:

```
WRONG  8afb29e991c9ba487a3a3b77a7eb4fc22260889495951b53b066f707c5616be1
       = the correct document with a trailing newline appended
         (the file IS the canonical bytes; nothing is appended, 6.1)

WRONG  913c160e6d268e32ed424aad30db11e790e7918ee5155d574c86f4ab1bca8e08
       = deduplication by name instead of by purl, dropping leaf 0.2.0
         and leaving two components (Section 3, rule 3)
```

---

## 7. Verification: `verify-sbom`

### 7.1 Invocation

```
verify-sbom --kind <cargo|composer|npm> --lockfile <f> [--manifest <composer.json>]
            --subject <purl> --sbom <f> [--third-party] [--dep-v0 <elf>]
```

The SBOM is the **untrusted** artefact; the lockfile, the manifest and the subject
belong to the auditor. `--manifest` is accepted only for `--kind composer`, the one
projection that reads a root manifest (4.2); supplying it elsewhere is a usage error
rather than a silently ignored flag, because an auditor who believes a manifest was
consulted when it was not has been misled. Implementations SHOULD bound resource use
over adversarial input, refusing an oversized file loudly rather than allocating.

An auditor who holds the lockfile must also be able to PRODUCE the projection, since
verifying *is* producing and comparing. The companion subcommand is:

```
emit-sbom   --kind <cargo|composer|npm> --lockfile <f> [--manifest <composer.json>]
            --subject <purl> --out <f>
```

It writes the canonical bytes of Section 6 to `--out` and prints their SHA-256, and
nothing else, on standard output, so that `sha256sum <out>` reproduces the printed
digest with stock coreutils. It verifies nothing, so exit 1 is not in its vocabulary
at all (7.6).

### 7.2 The subject is never read from the document under test

`--subject` is mandatory. A verifier MUST re-derive the projection with the supplied
subject and compare the **whole** document, `metadata.component` included. It MUST NOT
read the subject from the SBOM's own `metadata.component`, for the same reason an audit
package can never name its own trust anchor: an artefact declaring what it is supposed
to be is evidence of nothing. A forged `metadata.component` presented with a legitimate
`--subject` MUST fail.

### 7.3 Comparison semantics: two verdicts, never conflated

1. **Byte-identical.** The bytes of the SBOM equal the bytes of the re-derived
   projection (Section 6). This is the only **strong** verdict and the expected outcome
   for a document this projection produced.
2. **Semantic difference.** Otherwise the verifier reports difference *sets* -- never a
   summary judgement of "equivalent": purls only in the SBOM; purls only in the
   projection; purls in both at different versions; top-level purls in only one of the
   two `dependsOn` sets.

An implementation MUST NOT report the byte-identical verdict merely because the
difference sets are empty; collapsing the two makes canonicalisation pointless. That
case -- differing bytes with every difference set empty -- is its OWN named outcome and
it FAILS: the document differs in something the difference sets do not enumerate, which
is exactly the situation the canonical form exists to make visible. Comparison MUST
include the `dependencies` array -- ignoring it is the exact silent failure this
projection exists to close.

### 7.4 Third-party documents

A CycloneDX document from another tool is compared, not rewritten. Regenerating it in
this format is forbidden by Section 1.2, and it is not held to Section 5 either: a
document that never claimed to be this projection cannot be judged non-conforming for
carrying a `serialNumber`.

That comparison is reached through an explicit `--third-party` flag, and it is a
**lenient** path with one binding property: **it never reports a match.** Every input it
can read at all exits 1. The reason is structural, not empirical: the bytes it compares
are not the bytes the producer published. To compare at all it must first ADAPT the
document, and byte identity over an adapted document is a statement about the
adaptation, not about the artefact. The strong verdict of 7.3 is therefore unavailable
on this path by construction. An implementation MUST NOT print the fixed match banner of
7.7 here, and MUST NOT exit 0 here, even when the adapted document reduces to the
projection exactly.

An implementation MUST apply no adaptation beyond the following six, and MUST report
each one it applied, by name, in its output. A reduction applied silently is
indistinguishable from a difference that was hidden.

1. Top-level keys outside the seven of 5.1 are DROPPED -- `serialNumber` above all.
2. `metadata` keys other than `component` are DROPPED -- `timestamp`, `tools`.
3. An ABSENT `components`, `dependencies` or `properties` is compared as an empty array.
   Absence and emptiness say the same thing about those three containers, and the
   difference sets then report the whole projection as missing, which is the honest
   answer. The scalar header fields `bomFormat`, `specVersion` and `version` are
   deliberately NOT in this list: supplying one would invent a value the document never
   stated, which is a forgery rather than an adaptation.
4. `components` are re-sorted ascending by purl (5.2).
5. An object that declares a `purl` and NO `bom-ref` is given its purl as the reference
   (5.3).
6. A `bom-ref` that is present and DIFFERENT from its own `purl` is REWRITTEN to the
   purl, the foreign identifier is DISCARDED, and every `ref` and `dependsOn` entry that
   named it follows the rewrite, so that the reduction does not itself leave a reference
   dangling. Leaving it untouched made this whole path unreachable for the tool an
   auditor is most likely to hold: `cargo-cyclonedx` writes cargo package-ids
   (`registry+https://...#name@version`, `path+file:///...#name@version`) as `bom-ref`,
   so EVERY document of its shape stopped at `bom-ref-not-purl` before a single
   difference set was computed. What is discarded is a reference space of the document's
   own -- a real loss, and the reason this reduction is reported by name like the
   others. What is gained is the comparison itself, and the purls, which is where a
   disagreement between two tools is legible.

   The count an implementation reports for this reduction is the number of **objects**
   rewritten, not the number of distinct identifiers discarded. A foreign `bom-ref`
   declared by **two** objects MUST NOT be reduced at all: there is no single purl to
   retarget the references that named it to, and taking the last object read points the
   graph at whichever one happened to come later. It MUST be refused under the error
   class `duplicate-foreign-bom-ref` and exit 1 -- a `bom-ref` is unique within a
   document under CycloneDX's own rule, so this is the document's failure, not the
   auditor's.

The adapted document is then re-serialised in the canonical form of Section 6 and read
as in 7.3. Anything it still violates -- a duplicate purl, a reference resolving against
nothing, a component declaring no purl at all -- is reported by error class and the run
fails. The lenient path never rewrites a document into conformance.

Without `--third-party` the strict path applies unchanged. A foreign document normally
fails it before any comparison, as non-canonical: another tool's output is rarely the
JCS form of the value it encodes.

### 7.5 Optional check: SBOM against a binary

When `--dep-v0 <path>` is supplied, and only then, the verifier also reads the
dependency list embedded in the binary itself -- the `.dep-v0` section written by
`cargo auditable`, a zlib-compressed JSON blob located through the ELF section table --
and compares it with the projection. The flag is accepted only for `--kind cargo`: a
`.dep-v0` section lists cargo crates, so against another ecosystem's projection every
pair would be reported missing, which is a guaranteed failure that means nothing.

- Every `(name, version)` pair in `.dep-v0` MUST be present as a component of the
  projection. A pair that is absent is a **failure**. The pair naming the subject itself
  is covered by `metadata.component`: entry 0 of a `.dep-v0` document is the root
  package the binary was built from, and Section 5.5 deliberately keeps the subject out
  of `components`, so treating that pair as unaccounted would fail every instrumented
  binary on its own crate. Both halves of the pair still participate: a root at another
  version, or under another name, is not the subject.
- Components of the projection absent from `.dep-v0` are **not** a failure and MUST be
  reported as informational: a lockfile covers a whole workspace while a `.dep-v0`
  section covers what was compiled into one binary, so the second is a subset of the
  first by construction.
- A binary with **no** `.dep-v0` section is an outcome distinct from a mismatch. It MUST
  be reported as `SBOM<->binary: NOT ATTESTED (binary carries no .dep-v0 section)` and
  MUST exit non-zero: a check that was requested and could not be performed is not a
  pass.
- A non-ELF container (PE, Mach-O), or an image that cannot be read at all, MUST fail
  loud as an unsupported binary format, never return an empty list, and is the
  **AUDITOR's** error: exit 2 (7.6). They asserted the path named an ELF image and it
  does not. That is the opposite claim from the bullet above: a valid ELF with no
  section says the PRODUCER attested nothing, and exits 1.
- The section MUST be located through the section table. Searching the raw bytes for
  `.dep-v0` finds the name in the string table and returns rubbish.
- An image carrying **more than one** section of that name MUST fail loud as a malformed
  ELF. Which of them describes the binary is not decidable, and answering from the first
  leaves the other unread behind a clean verdict.

### 7.6 Error classes and exit codes

| Class | Examples | Exit |
|---|---|---|
| match | byte-identical, and every requested optional check passed | `0` |
| verification failure | semantic difference; differing bytes with empty difference sets; unreadable or malformed SBOM; when `--dep-v0` was given: a `.dep-v0` mismatch, an absent section, or an ELF image whose section cannot be decoded; **every** `--third-party` run whose document could be read at all | `1` |
| auditor-side / usage error | `--subject` missing, malformed, or of a purl type other than the one `--kind` names (5.5); lockfile or manifest unreadable, malformed or of unsupported shape; `--manifest` outside `--kind composer`; `--dep-v0` outside `--kind cargo`, or naming a file that is unreadable or is not an ELF container at all; a flag supplied twice; unknown option or unknown `--kind`; a `--third-party` document that is not JSON at all | `2` |

The asymmetry is deliberate: a script filtering for "the vendor's artefact failed" must
not be contaminated by the auditor's own typo. Two consequences of it are worth naming.

The `--dep-v0` leg splits the same way. A file that is not an ELF image, or that cannot
be read at all, falsifies what the auditor asserted about their OWN input and exits 2; an
ELF that carries no `.dep-v0` section falsifies nothing of theirs -- it says the producer
attested nothing -- and exits 1. A malformed ELF stays on the vendor's side of the line:
the magic says ELF, so what is broken is the image, which is the artefact under audit.

An unreadable `--sbom` file is a verification failure (1) on the strict path, where the
document IS the material under audit, but a usage error (2) under `--third-party`, where
the auditor has ASSERTED that the file is a foreign CycloneDX document: a file that is
not JSON at all falsifies the assertion, not the artefact. Nothing is lost by the
distinction, since `--third-party` never returns 0 and so carries no vendor-failure
signal of its own to protect.

`emit-sbom` verifies nothing, so it MUST NOT exit 1 on any input. It writes the file and
exits 0, or one of the auditor's own inputs was unusable and it exits 2 having written
nothing.

Error classes an implementation MUST distinguish by name: `UnsupportedLockShape`,
`MissingVersion`, `AmbiguousDependencyRef`, `PurlCollision`, `MalformedManifest`,
`UnsupportedBinaryFormat`.

### 7.7 Output vocabulary

Success prints the **fixed** banner `SBOM matches the lockfile projection` followed by
the substantive counts -- components and top-level entries -- so a match over zero
components cannot be read as a substantive approval. That banner belongs to the strong
verdict of 7.3 alone; `--third-party` MUST NOT print it (7.4).

The banner is printed only once **every requested optional check has also passed**, and
a run that exits non-zero MUST NOT print it at all. It is the line downstream tooling
greps for, so a byte-identical document beside a `--dep-v0` image that fails would
otherwise carry the success banner out on the stdout of a run that exits 1.

The token `VERIFIED` is RESERVED for this product's strong verification surfaces.
`verify-sbom` is not one of them and MUST NOT emit it, including inside an error message
that interpolates bytes taken from the SBOM. An implementation SHOULD sanitise the
reserved token at its output boundary, since downstream tooling pattern-matches that
substring as a strong pass.
---

## 8. Reproducibility

A conforming implementation MUST satisfy all six. They are stated as tests because each
is a falsifiable claim, not an aspiration.

1. **Frozen bytes.** The reference vector of 6.2 reproduces exactly, hash included.
   This single pin is what makes a change of serializer, key order, array order or
   number encoding observable.
2. **Line-ending independence.** Projecting a lockfile whose `\n` have all been replaced
   by `\r\n` yields identical bytes and hash. The substitution MUST be performed **at
   test time**, in memory: committing a CRLF fixture tests nothing, because a repository
   that normalises line endings on checkout hands the test an LF file and the test
   certifies its own copy.
3. **Byte-order mark.** A lockfile beginning with a UTF-8 BOM MUST be rejected loudly,
   never parsed into a first package whose name silently carries the BOM character.
4. **Two-run stability.** Projecting the same input twice in one process yields
   identical bytes -- the test that catches unordered map iteration.
5. **Platform independence.** The pin of item 1 MUST be executed on at least two
   operating systems; if they disagree by one byte, one goes red against the same
   constant. The mechanism is a RE-DERIVATION, not a recorded manual run: the pins are
   computed on the developer's machine (Windows) and re-derived against the same
   committed constants by the continuous integration on Linux
   (`.forgejo/workflows/security.yml`, job `cargo-test`, step `cargo test (workspace,
   lib + integration)`). An implementation whose pins have never been re-derived on a
   second platform MUST NOT claim platform independence.
6. **Real-lockfile invariants.** Over the project's actual lockfiles: the projection
   completes without error, component order is total, purl collisions are zero, and the
   top-level set is non-empty. These assertions MUST NOT pin component counts, which
   change legitimately with every dependency bump.

---

## 9. Versioning

| Axis | Where it lives | Meaning |
|---|---|---|
| Spec version | this document's title | revision of this specification |
| Projection id | `seetrex:sbom.projection`, currently `lockfile-v1` | the byte-level contract of the emitted document |

A change is **breaking** -- requiring a new projection id, `lockfile-v2` -- if it can
change the bytes emitted for any input that was already valid: adding, removing or
renaming an emitted key; changing a purl form; changing a sort key or direction;
changing the canonicalisation, the line policy or the encoding; changing how the
top-level set is derived; changing a `top_level_basis` literal; or narrowing what is
accepted as input.

A change is **non-breaking** if it cannot alter the bytes of any previously valid input:
accepting a lockfile format version that was previously rejected, adding an ecosystem
with its own purl type and basis literal, adding an error class for input already
rejected, or editing this text.

When the projection id changes, the reference vector of 6.2 is recomputed **in the same
change** that alters the behaviour -- never afterwards, which would leave a window where
specification and implementation disagree and nothing goes red.

---

## 10. Conformance checklist

Every line is observable from outside the implementation.

- [ ] Reads only the fields of 2.1-2.3; fails loud on any unsupported input shape.
- [ ] Emits no `licenses`, `author`, `supplier`, `description`, `externalReferences`,
      `copyright`, `cpe`, `swid`, `integrity`, `dist.shasum` or `dist.reference` (2.4).
- [ ] `hashes` appears only in cargo documents, only on entries with a `checksum`, and
      only under the `SHA-256` label (5.2); a composer or npm document contains the
      substring `hashes` nowhere.
- [ ] Purls match the grammar of Section 3, with `%40` on npm scopes only.
- [ ] Versions are verbatim; a missing version is an error, not an omitted key.
- [ ] Deduplication is by exact purl; same purl with a different payload is
      `PurlCollision`.
- [ ] `components` is sorted by purl over UTF-8 bytes and excludes the subject.
- [ ] Every component and `metadata.component` carries a `bom-ref` equal to its own
      purl, so every `ref` and `dependsOn` entry resolves against a declared one.
- [ ] `dependencies` has exactly one entry, `ref` = the subject purl, `dependsOn` = the
      sorted top-level set.
- [ ] The top-level set follows 4.2, composer platform requirements excluded and
      counted.
- [ ] Exactly the seven top-level keys of 5.1; no `serialNumber`, no
      `metadata.timestamp`, `metadata` carrying only `component`.
- [ ] `metadata.component` derives from the supplied subject and only from it, and
      carries exactly the five keys of 5.5 -- no `group`, whatever the ecosystem.
- [ ] The `seetrex:` properties are BOM-level, sorted by name, carry the literals of
      5.4, and no consumer rule depends on them.
- [ ] Output is JCS, one line, no trailing newline, no BOM, and
      `sha256(file) == sha256(JCS(document))`.
- [ ] The reference vector of 6.2 reproduces byte for byte, and neither negative control
      of 6.3 is produced.
- [ ] `verify-sbom` requires `--subject` and never reads it from the document under
      test.
- [ ] The two verdicts of 7.3 are never conflated and `dependencies` is part of the
      comparison.
- [ ] Exit codes follow 7.6; the reserved token never reaches the `stdout` or the
      `stderr` of `verify-sbom` or `emit-sbom`. The obligation is on those verdict
      surfaces and not on the artefact: the canonical bytes are a faithful projection
      and MAY carry the token, because a dependency whose real name contains it is
      projected under its real name rather than renamed.
- [ ] All six obligations of Section 8 are executed, not asserted -- item 5 by a second
      operating system re-deriving the same committed pins in continuous integration,
      never by a run somebody says they performed.

---

## Appendix A. Editorial completions

To be implementable this specification had to fix points its source decision record left
open. They are listed so a reviewer can challenge each on its own rather than discover
it inside the prose.

1. **`bom-ref` is written explicitly** (5.3): the source record states that the purl
   *is* the `bom-ref`, while its own worked output -- abbreviated, not normative --
   showed no such key. Resolved towards the literal decision and towards strict
   CycloneDX resolution, since a dangling `ref` would make the document invalid for the
   very auditors this format serves. That the chain normaliser drops the key on
   ingestion is a property of the chain's canonical form, not of this artefact.
2. **The subject is excluded from `components`** (5.5), and every other lockfile entry,
   workspace members included, is a component. The source record says neither.
3. **`metadata.component` carries exactly `bom-ref`, `type`, `name`, `purl`,
   `version`** -- five keys, and never a `group`, whatever the ecosystem: decoding a
   namespace back out of the purl is a transformation, and the purl already carries it
   verbatim. `type` is fixed to `"application"`. The source record shows the shape in an
   example but states no rule. (This entry admitted the key for a namespaced purl until
   it was corrected: it contradicted 5.5 and the checklist of Section 10, which both
   forbid it, and Appendix A is where a reviewer looks for the rule.)
4. **`top_level_basis` literals for composer and npm** (5.4): only the cargo literal was
   pinned upstream; `composer-json-require-merged-dev` and
   `npm-lock-root-dependencies-merged-dev` are now normative.
5. **`platform_requirements_excluded` is a decimal string** -- CycloneDX property values
   are strings, while the source record shows a count.
6. **Binary comparison direction** (7.5): `.dep-v0` is a subset of the projection, so
   pairs missing from the SBOM fail while components missing from the binary do not.
   The source record specifies extraction, not comparison.
7. **A manifest key resolving to no lockfile entry fails loud** (4.2): the source record
   specifies the key sets but not this case.
8. **Property array ordering** is ascending by name (5.4), inferred from the upstream
   example rather than stated by it.
9. **`seetrex:sbom.links_omitted`** (5.4, 2.3): the source record omits npm `link`
   entries and counts them but defines no property to carry the count; this document
   defines one, on the model of the composer exclusion counter.

## Appendix B. Known deviations from generic CycloneDX tooling

- References resolve normally: `bom-ref` is declared on every component and equals the
  purl (5.3). The one thing a downstream reader must not assume is that the key survives
  ingestion into this product's evidence chain, whose canonical form drops it for every
  document alike; the published bytes are the contract, and `verify-sbom` checks them.
- The absence of `serialNumber` is legal in 1.5 but unusual; tools keying their storage
  on it need another key. The purl of `metadata.component` plus the document hash is the
  intended identity.
- The graph is deliberately depth 1 (4.1). A tool reading `dependencies` as a complete
  graph will conclude, wrongly, that the transitive dependencies have no edges. They are
  not claimed to have none: they are not claimed at all.
