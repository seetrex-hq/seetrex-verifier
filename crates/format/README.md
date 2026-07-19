# seetrex-format

The pure format layer of the Seetrex Compliance verdict package: the
serializable types (`Fact`, `FactValue`, `AuditEntry`, `Rule`, `Condition`,
`Operator`) and the JCS RFC 8785 canonicalization/hashing primitive. The
serde shape of these types IS the public package format — this crate defines
shape, not behavior. It contains no inference logic, no database, no network
and no HTTP dependencies (enforced by `test_intent_format_crate_is_pure`).

`seetrex-verifier` builds on this crate to verify packages offline.

## Open-source boundary

Same boundary as the Seetrex verification stack: `seetrex-format`, `seetrex-verifier` and the
package specification are open (Apache-2.0); the inference engine, the
derivation dispatcher, the connectors and the SaaS backend are closed. The
open crates give full independent verification of registry integrity
(hashes, evidence, chain, anchor); re-deriving a verdict outcome re-runs the
engine, which is available as a signed reproducible binary or as a source
rebuild under NDA. See `crates/verifier/README.md` for the full statement.

## Spec

The byte-level package format is specified in
`docs/SPEC_VERDICT_PACKAGE_V1.md`.
