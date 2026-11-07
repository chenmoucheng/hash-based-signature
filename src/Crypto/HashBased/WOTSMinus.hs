-- | WOTS-: deliberately insecure WOTS without checksum chains, for experiments.
-- SHA-256, radix 16, 64 chains. Never use this toy to protect real data.
-- Secret-key single use is an obligation, not enforced consumption.
module Crypto.HashBased.WOTSMinus
  ( SecretKey, PublicKey, Signature
  , generateKeyPair, publicKey, signOnce, verify
  , winternitzBase, chainCount, signatureSize
  ) where

import Crypto.HashBased.WOTS.Internal (winternitzBase)
import Crypto.HashBased.WOTSMinus.Internal
