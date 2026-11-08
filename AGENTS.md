# Repository guidance

## Purpose and source of truth

This repository is a minimal Haskell framework for human development of hash-based
signatures. Read `SPEC.md` and `PLAN.md` before changing code. `SPEC.md` defines the
requirements; `PLAN.md` defines the initial scope and implementation sequence.
Keep changes small enough for a human to review and explain material design choices.

## Project conventions

- Use Stack for builds and dependency management. Maintain a single Cabal package
  with one library and one test suite initially; do not introduce a second package
  description generator.
- Pin the Stack snapshot and commit dependency lock information. Check snapshot,
  compiler, package, and native-library compatibility before selecting versions.
- Use an existing wrapper package for native hash implementations. Keep it behind
  `Crypto.HashBased.Hash`; do not implement hashes or introduce custom FFI.
- Keep schemes in separate `Crypto.HashBased.<Scheme>` modules. Prefer concrete
  types and explicit functions. Introduce shared abstractions only for demonstrated
  reuse, and keep the public API small.
- Document native dependencies and reproducible setup commands in `README.md`.
  Do not add unrelated tooling, applications, or extra schemes to a focused change.

## Cryptographic implementation rules

- Identify the construction and source being implemented. Record parameters,
  message preprocessing, bit ordering, encodings, and domain separation where
  applicable. Do not silently substitute a related variant.
- Start with WOTS in `Crypto.HashBased.WOTS`, using the fixed parameters selected
  in the implementation plan. Document the exact construction; WOTS+ requires an
  explicit scope decision. Test base conversion, checksum encoding, and chain
  bounds independently, and derive sizes from the selected parameters.
- Keep the requested checksum-free WOTS- toy in `Crypto.HashBased.WOTSMinus`
  with distinct types. Preserve its educational insecure status, SHA-256 default
  message preprocessing, and tests demonstrating digest-level forgery without checksums.
  Do not present chosen-digest attacks as message-preimage attacks.
- Use established cryptographic randomness for key generation. Keep deterministic
  fixtures in tests; never add a production fallback to predictable randomness.
- Preserve the public entropy-generation and pure key-generation phases in both
  variants. Validate entropy length, document raw entropy as secret-key material,
  and keep `generateKeyPair` as their composition. Caller-supplied bytes must be
  fresh cryptographic randomness; size validation does not establish their quality.
- Hide constructors when necessary to preserve length or parameter invariants.
  Validate untrusted byte inputs and return explicit failures for malformed values.
- Preserve public `signDigest` and `verifyDigest` in both variants, operating on
  `Digest` without an extra prehash. Message-level wrappers hash exactly once.
  Single-use obligations apply across all signing entry points for a key.
- Support caller-selected message hashes and digest sizes with `MessageHash` and
  the `…With` interfaces. Validate output lengths and derive chain/checksum/entropy
  sizes; keep native SHA-256 chain hashing separate. Preserve the default API and
  test non-32-byte digests, checksum-width boundaries, and malformed callback output.
- Do not log secret keys, derive printable representations for them, or claim
  constant-time behavior, memory erasure, or production security without evidence.
- Keep signature Text export canonical lowercase hex in chain order. Validate
  characters and exact configured payload length on import; parsing is separate
  from verification. Do not imply the payload contains scheme/hash metadata.
- One-time keys must never be reused. Document the reference API's inability to
  enforce key consumption. Do not describe ordinary immutable values as enforcing
  single use.
- Before implementing stateful signing, specify durable atomic state updates,
  concurrency behavior, crash recovery, and rollback protection. Do not hide state
  inside a generic stateless signing API.

## Validation and handoff

Run `stack build --test` for code or dependency changes once the project is
bootstrapped. CI must run that command on Linux for pushes and pull requests and
install native prerequisites explicitly. If validation cannot run, report why;
do not report unexecuted checks as passing.

Test hashes with published vectors and schemes with independent fixtures plus
positive and negative cases. Round trips alone are insufficient. Cover malformed
input at exposed parsing boundaries. Keep tests deterministic and small enough
for basic CI.

For documentation-only changes, check consistency with `SPEC.md`, `PLAN.md`, and
the actual repository; a build is unnecessary. In the final handoff, summarize
what changed, validation performed, and any unresolved limitations. Update the
plan when an agreed scope or design decision changes.
