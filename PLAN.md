# Minimal hash-based signature framework

## Goal and scope

Support human development of multiple hash-based signature implementations in
Haskell. Follow `SPEC.md`: manage the project with Stack, use an existing Haskell
wrapper around a native hash implementation, and run basic tests in CI.

The first deliverable is a small, understandable library and a working reference
scheme. It is an experimental development framework; production readiness requires
separate security review. Prefer explicit functions and scheme-specific types over
a universal signature interface.

## Minimum structure

Use one Stack project containing one library and one test suite:

```text
stack.yaml
hash-based-signature.cabal
src/Crypto/HashBased/Hash.hs
src/Crypto/HashBased/WOTS.hs
src/Crypto/HashBased/WOTSMinus.hs
test/Main.hs
.github/workflows/ci.yml
README.md
SPEC.md
PLAN.md
AGENTS.md
```

Maintain the Cabal file directly; do not also maintain a `package.yaml`. Pin a
Stack snapshot and commit dependency lock information. Select the snapshot and
dependencies together after verifying compatibility on the development platform
and Linux CI.

### Hash boundary

Put the chosen native hash wrapper behind `Crypto.HashBased.Hash`. Begin with one
fixed-output hash algorithm and one concrete digest type. Expose only the hashing
operation and byte conversion needed by the reference scheme; keep backend details
out of scheme modules. Verify that the dependency actually uses a native
implementation, and document its native libraries, compiler requirements, license,
and installation steps. Do not write a new FFI binding or a pure Haskell hash.

Message hashing is now caller-configurable through `Crypto.HashBased.MessageHash`:
an opaque configuration pairs a positive digest size in bytes with a pure
`ByteString -> ByteString` callback. Both schemes expose `…With` operations for
key generation, derived sizes, message signing, and raw-digest signing. Validate
callback output and digest lengths, derive message/checksum chain counts from
the configured size, and reject overflowing sizes. Keep the existing API as the
SHA-256/32-byte default. Chain hashing remains native SHA-256 with 32-byte nodes.
Preserve each scheme's domain separation and input encodings exactly. Callers
must use the same configuration consistently; keys do not encode hash identities.

### Scheme modules

Start with Winternitz one-time signatures (WOTS) as the end-to-end reference. Keep its
key, signature, and parameter types in its own module, with constructors hidden
where they could admit malformed values. Provide explicit key generation,
signing, and verification functions. Fix parameters initially, document message
preprocessing, and make invalid sizes fail explicitly rather than crash.

Select and cite the exact WOTS construction before implementation; do not silently
substitute WOTS+. Keep base conversion, checksum encoding, and hash-chain logic
as small internal functions that can be tested independently. Fix the Winternitz
parameter and hash output size for the first implementation, deriving chain counts
and signature sizes from the selected construction rather than duplicating constants.

Use an established cryptographic randomness dependency for key generation; never
use a general-purpose PRNG. Keep deterministic test inputs separate from the
production key generation path. Avoid printable secret-key representations.

Both variants expose `generateEntropy :: IO ByteString` and pure
`keyPairFromEntropy :: ByteString -> Maybe (SecretKey, PublicKey)`, with
`entropySize` specifying the exact required length. Retain `generateKeyPair` as
their convenience composition. Entropy bytes are secret-key material, not a short
seed; callers must supply fresh cryptographic randomness. Invalid lengths return
`Nothing`, and deterministic fixtures remain test-only.

Both variants expose `signDigest :: SecretKey -> Digest -> Signature` and
`verifyDigest :: PublicKey -> Digest -> Signature -> Bool`. These use the supplied
digest directly. Keep message-level `signOnce` and `verify` as wrappers that hash
once. `Crypto.HashBased.Hash` provides hashing and validated digest import. Single
use applies across all signing entry points; tests cover fixture agreement, raw
digest handling without another prehash, and wrong-digest/key rejection.

WOTS keys may sign only once. Use a conservative initial API: expose an
explicitly named one-time signing function with this precondition documented at
the call site and in the README. Haskell values are copyable, so the API does not
enforce consumption or prevent key reuse. Do not imply that it does.

Future schemes get separate modules and their own APIs. Extract common utilities
only after two implementations demonstrate the same need. A stateful scheme must
define state ownership and a durable, atomic update strategy before exposing a
usable signing API; a shared stateless interface must not hide these requirements.

## Implementation sequence

The initial implementation selects SHA-256, radix `w = 16`, 64 message digits,
and three checksum digits (67 chains). `README.md` defines the precise plain-hash
WOTS construction and sources. Stack uses `lts-22.44` / GHC 9.6.7,
`cryptohash-sha256-0.11.102.1`, and `entropy-0.4.1.11`. The test runner uses `base`
without a separate test framework. A private `WOTS.Internal` module supplies test
seams; one small example executable demonstrates the public API.

Implemented and validated locally on Apple Silicon: the library, example,
independent fixtures, and tests pass with `stack build --test --system-ghc`.
Linux CI is configured but has not yet been run remotely. Adding a second scheme
remains a separately scoped task.

The subsequently requested WOTS- toy variant is implemented separately in
`Crypto.HashBased.WOTSMinus`. It removes all checksum chains, leaving 64 chains
and a 2048-byte signature payload, while retaining the same message prehash and
chain rules. It has distinct opaque types, reuses private WOTS digit/chain helpers,
and adds independent fixture checks plus a digest-level forgery demonstration.
It is intentionally insecure and does not expand scope to production variants.

1. **Bootstrap the project.** Choose and pin a compatible Stack snapshot, native
   hash wrapper, randomness dependency, and small test dependency. Add the library,
   test target, and README setup instructions. Confirm a clean `stack build`.
2. **Implement the hash boundary.** Add the concrete digest type and minimal
   operations. Check published known-answer vectors, including empty input, and
   confirm native dependencies can be installed on a fresh CI runner.
3. **Implement the reference scheme.** Choose and cite a precise WOTS
   construction, including hash algorithm, Winternitz parameter, derived sizes,
   digit ordering, checksum encoding, chain rules, and message preprocessing.
   Implement key generation, one-time signing, and verification.
   Add a short runnable usage example and clearly explain the key-reuse hazard.
4. **Add tests and CI.** Run `stack build --test` on Linux for pushes and pull
   requests. Install required native dependencies explicitly. Caching is optional;
   correctness must not depend on it.
5. **Review the extension path.** Document how a human adds a scheme module,
   specifies its parameters and security assumptions, supplies test vectors, and
   registers its tests. Add the second scheme only as a separately scoped task;
   revise shared code based on that implementation's actual requirements.

## Minimum tests

- Hash known-answer vectors against an independently published source.
- A valid reference-scheme signature verifies, including an empty message.
- Changed messages, changed signatures, and a different public key are rejected.
- Base conversion covers digit ordering and boundary values; checksum fixtures
  cover its calculation, padding, and encoding under the selected construction.
- Hash chains cover zero steps, the maximum valid number of steps, and invalid
  bounds. Exercise every digest digit position and include all-zero and all-one
  digest fixtures at the internal test seam.
- Malformed lengths are rejected at any byte-input boundary that is exposed.
- Repeatable fixtures exercise the scheme without relying only on a sign/verify
  round trip, which could share the same bug. Cite fixture provenance or describe
  an independent derivation.

## Completion criteria

A fresh checkout can follow the README to build and run tests with Stack; Linux
CI passes the same command. The hash backend uses an existing native wrapper,
WOTS works with the documented fixed parameters, tests cover acceptance and
rejection, and a contributor can identify where a second scheme belongs without
changing a central framework interface.

## Deferred work

No CLI, service, plugin registry, general signature typeclass, benchmark suite,
custom FFI, key storage, or broad scheme catalog in the initial framework.
The requested signature import/export uses canonical lowercase hexadecimal Text
for concatenated chain values, with default and configured-size parsers. Import
accepts either hex case and rejects invalid characters or lengths. Scheme/hash
metadata and secret-key persistence remain out of scope. Public keys expose
`publicKeyToText`, `publicKeyFromText`, and `publicKeyFromTextWith` for ordered
chain endpoints, sharing the private hex codec. Payloads have no type tags;
parsing cannot authenticate keys or distinguish key text from signature text.
Tests cover independent fixtures, leading zeros, malformed text, and verification
after importing both signatures and public keys. Secure
persistence and rollback protection are
prerequisites for supporting stateful signing, not implicit features of this MVP.
