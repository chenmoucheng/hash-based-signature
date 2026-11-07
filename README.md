# Hash-based signatures

A minimal experimental Haskell library for developing hash-based signatures.
The first scheme is plain hash-chain WOTS with SHA-256 and base 16. This is a
development reference, without a production security review.

## Build and run

Install Stack 3.3.1 (the version used in CI), a C compiler, and standard native
build tools. The pinned `lts-22.44` snapshot selects GHC 9.6.7 and dependency
versions; `stack.yaml.lock` records the snapshot content hash. Stack can install
GHC, or use an existing matching compiler with `--system-ghc`.

Use the same compiler selection for both build and execution. When building with
`stack build --test --system-ghc`, run `stack exec --system-ghc wots-example` too.
CI uses this pair so both steps share the same compiler and installation paths.

On Ubuntu 24.04:

```sh
sudo apt-get update
sudo apt-get install -y build-essential libgmp-dev zlib1g-dev
stack build --test
stack exec wots-example
```

On macOS, install the Xcode command line tools (`xcode-select --install`), then run
the same Stack commands. The implementation has been built and tested on Apple
Silicon with GHC 9.6.7. Linux CI runs the build, tests, and example on pushes and
pull requests.

The example prints `True` and uses a fresh key exactly once:

```haskell
import qualified Data.ByteString.Char8 as BS
import Crypto.HashBased.WOTS

main :: IO ()
main = do
  (secret, public) <- generateKeyPair
  let message = BS.pack "hello WOTS"
      signature = signOnce secret message -- Never use secret again.
  print (verify public message signature)
```

`generateKeyPair` obtains cryptographic entropy through `entropy`; failures
propagate as IO exceptions. Secret-key constructors and deterministic key import
are private. Public keys and signatures are opaque in-memory values; there is no
wire format or key persistence API.

**A WOTS secret key must sign at most one message.** `signOnce` names the obligation
but does not enforce it: immutable Haskell values can be copied and reused. This
library does not provide durable key consumption, concurrent signing control,
rollback protection, secret-memory erasure, or constant-time guarantees.

## Exact construction

We instantiate the basic hash-chain/checksum WOTS construction described in
Section 2 of Wagner et al.,
[Faulting Winternitz One-Time Signatures](https://eprint.iacr.org/2023/1572).
The following choices define this repository's variant completely; it is not
WOTS+, WOTS-PRF, or an XMSS/LMS-compatible implementation.

- `H(x) = SHA256(x)`, with a 32-byte output. Messages are arbitrary bytes and are
  prehashed once as `H(message)` before digit conversion.
- `w = 16` denotes the radix, not the number of bits per digit. Read each digest
  byte high nibble first, in byte order: `len1 = 256 / 4 = 64` digits.
- Compute `c = sum(15 - digit)`. Its maximum is 960, so
  `len2 = floor(log_16(960)) + 1 = 3`. Append the checksum as exactly three
  most-significant-first hexadecimal digits, with leading zero padding. There is
  no additional byte-alignment shift. For an all-zero digest append `3,c,0`; for
  an all-one digest append `0,0,0`.
- A secret key contains `len = len1 + len2 = 67` independent random 32-byte
  values. Each chain is `H` applied repeatedly to its secret value, with no salts,
  address inputs, masks, or domain-separation prefixes.
- The public key contains all 67 endpoints `H^15(secret[i])`, in order. The
  signature contains `H^digit[i](secret[i])`, where `H^0` is the identity.
  Verify by advancing each signature element `15 - digit[i]` steps and comparing
  all endpoints. Signature and public-key payloads are each 2144 bytes; this does
  not include Haskell runtime overhead or define a serialization format.

This choice deliberately retains the basic plain-hash construction. Security
claims for PRF-based WOTS or WOTS+ are not claims about this implementation.

## Dependencies

| Package | Version | Role / native requirements | License |
| --- | --- | --- | --- |
| [cryptohash-sha256](https://hackage.haskell.org/package/cryptohash-sha256-0.11.102.1) | 0.11.102.1 | Existing wrapper over bundled C SHA-256; needs a C compiler, no OpenSSL installation | BSD-3-Clause |
| [entropy](https://hackage.haskell.org/package/entropy-0.4.1.11) | 0.4.1.11 | Platform cryptographic entropy; C feature probes and OS entropy APIs | BSD-3-Clause |

`base` and `bytestring` come from the pinned compiler/snapshot. There are no custom
FFI bindings. `entropy` may print failed feature probes for unavailable APIs while
configuring; it selects a supported platform source (including `/dev/urandom`
fallback on Unix). Failure to obtain entropy is not replaced by predictable data.

## Tests and extension

Run `stack build --test` from the repository root. The small test runner uses
`base` rather than an additional test framework. Tests cover SHA-256 known answers,
malformed digest lengths, every digest digit position and value, checksum padding,
all valid chain segments, invalid bounds, signature tampering, changed messages,
wrong keys, and fresh-key signing including the empty message.

`test/fixtures/wots.txt` contains complete public-key and signature fixtures for
`abc`, derived independently with Python's `hashlib`, hex-string digit conversion,
and direct hash loops. The publicly known deterministic secret is the byte stream
`0,1,...,255` repeated to 2144 bytes. It is for tests only. Regenerate explicitly
with `python3 test/generate-fixture.py`; normal tests use the committed fixture
without running Python. SHA-256 `abc` is also the published example in
[RFC 6234](https://www.rfc-editor.org/rfc/rfc6234.html); the empty-input known answer
is additionally checked against the same SHA-256 definition.

To add another scheme, create a separate `Crypto.HashBased.<Scheme>` module,
document the exact construction and parameters, register it in the Cabal file,
and add independent fixtures plus acceptance/rejection tests. Reuse the hash
boundary; extract other utilities only when a second implementation needs them.
Stateful schemes require a state persistence and atomic update design first.
See `SPEC.md`, `PLAN.md`, and `AGENTS.md` for scope and contributor guidance.

The package is not prepared for Hackage publication: a project license and
publication metadata have not been chosen. `cabal check` reports these omissions;
they do not prevent local Stack builds or tests.
