-- | Private implementation of the deliberately insecure checksum-free toy.
module Crypto.HashBased.WOTSMinus.Internal where

import Crypto.HashBased.Hash
import Crypto.HashBased.WOTS.Internal (advance, base16, winternitzBase, messageDigits)
import qualified Data.ByteString as BS
import System.Entropy (getEntropy)

-- Separate types prevent mixing WOTS and WOTS- keys or signatures.
newtype SecretKey = SecretKey [Digest]
newtype PublicKey = PublicKey [Digest] deriving (Eq)
newtype Signature = Signature [Digest] deriving (Eq)

chainCount, signatureSize :: Int
chainCount = messageDigits
signatureSize = chainCount * digestSize

-- Internal decoder shared by pure key generation and test fixtures.
secretKeyFromBytes :: BS.ByteString -> Maybe SecretKey
secretKeyFromBytes bytes
  | BS.length bytes /= signatureSize = Nothing
  | otherwise = SecretKey <$> chunks bytes
  where
    chunks bs
      | BS.null bs = Just []
      | otherwise = (:) <$> digestFromBytes (BS.take digestSize bs)
                         <*> chunks (BS.drop digestSize bs)

-- | Required number of fresh, secret random bytes for one key pair.
entropySize :: Int
entropySize = chainCount * digestSize

-- | Phase one: obtain secret entropy from the operating system.
-- IO failures propagate; never reuse or log the returned bytes.
generateEntropy :: IO BS.ByteString
generateEntropy = getEntropy entropySize

-- | Phase two: deterministically construct a key pair from exactly 'entropySize'
-- bytes. Returns Nothing for invalid lengths. The caller must ensure the bytes
-- are cryptographically random, secret, and fresh; length checking cannot do so.
keyPairFromEntropy :: BS.ByteString -> Maybe (SecretKey, PublicKey)
keyPairFromEntropy bytes = do
  sk <- secretKeyFromBytes bytes
  pure (sk, publicKey sk)

-- | Convenience composition of entropy generation and pure key generation.
generateKeyPair :: IO (SecretKey, PublicKey)
generateKeyPair = do
  bytes <- generateEntropy
  case keyPairFromEntropy bytes of
    Nothing -> ioError (userError "WOTS-: entropy source returned an invalid length")
    Just pair -> pure pair

publicKey :: SecretKey -> PublicKey
publicKey (SecretKey xs) = PublicKey (map (advance (winternitzBase - 1)) xs)

-- Private digest seams demonstrate the attack without claiming to find preimages
-- for chosen SHA-256 digest values.
signDigest :: SecretKey -> Digest -> Signature
signDigest (SecretKey xs) digest = Signature (zipWith advance (base16 digest) xs)

verifyDigest :: PublicKey -> Digest -> Signature -> Bool
verifyDigest (PublicKey pk) digest (Signature sig) =
  length pk == chainCount && length sig == chainCount &&
  zipWith advance remaining sig == pk
  where remaining = map (winternitzBase - 1 -) (base16 digest)

-- | Toy only. Single use is still required and is not enforced by the type.
signOnce :: SecretKey -> BS.ByteString -> Signature
signOnce sk = signDigest sk . hash

verify :: PublicKey -> BS.ByteString -> Signature -> Bool
verify pk message = verifyDigest pk (hash message)
