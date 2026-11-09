-- | Experimental fixed-parameter WOTS (SHA-256, base 16), not WOTS+.
-- Secret keys must be used at most once; this API cannot enforce consumption.
module Crypto.HashBased.WOTS
  ( SecretKey, PublicKey, Signature
  , generateEntropy, keyPairFromEntropy, entropySize
  , generateKeyPair, publicKey, signOnce, verify
  , publicKeyToText, publicKeyFromText, publicKeyFromTextWith
  , signatureToText, signatureFromText, signatureFromTextWith
  , signDigest, verifyDigest
  , generateEntropyWith, keyPairFromEntropyWith, generateKeyPairWith
  , signDigestWith, verifyDigestWith, signOnceWith, verifyWith
  , chainCountWith, signatureSizeWith, entropySizeWith
  , winternitzBase, chainCount, signatureSize
  ) where

import Crypto.HashBased.WOTS.Internal
