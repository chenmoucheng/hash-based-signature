-- | Experimental fixed-parameter WOTS (SHA-256, base 16), not WOTS+.
-- Secret keys must be used at most once; this API cannot enforce consumption.
module Crypto.HashBased.WOTS
  ( SecretKey, PublicKey, Signature
  , generateKeyPair, publicKey, signOnce, verify
  , winternitzBase, chainCount, signatureSize
  ) where

import Crypto.HashBased.WOTS.Internal
