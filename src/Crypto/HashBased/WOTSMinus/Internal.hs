-- | Private implementation of the deliberately insecure checksum-free toy.
module Crypto.HashBased.WOTSMinus.Internal where

import Crypto.HashBased.Hash
import Crypto.HashBased.MessageHash
import Crypto.HashBased.WOTS.Internal (advance, base16, base16Bytes, winternitzBase, messageDigits)
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

-- | Sign a supplied digest directly, without hashing it again. Toy only.
-- Use this secret key at most once across ALL signing entry points.
signDigest :: SecretKey -> Digest -> Signature
signDigest (SecretKey xs) digest = Signature (zipWith advance (base16 digest) xs)

-- | Verify a supplied digest directly, without hashing it again. Toy only.
verifyDigest :: PublicKey -> Digest -> Signature -> Bool
verifyDigest (PublicKey pk) digest (Signature sig) =
  length pk == chainCount && length sig == chainCount &&
  zipWith advance remaining sig == pk
  where remaining = map (winternitzBase - 1 -) (base16 digest)

-- | Hash the message once, then sign. Toy only; single use is not enforced.
signOnce :: SecretKey -> BS.ByteString -> Signature
signOnce sk = signDigest sk . hash

-- | Hash the message once, then verify. Toy only.
verify :: PublicKey -> BS.ByteString -> Signature -> Bool
verify pk message = verifyDigest pk (hash message)

-- | Number of chains for the selected message hash. Chain nodes remain SHA-256.
chainCountWith :: MessageHash -> Int
chainCountWith config = 2 * messageDigestSize config

signatureSizeWith, entropySizeWith :: MessageHash -> Int
signatureSizeWith config = chainCountWith config * digestSize
entropySizeWith = signatureSizeWith

-- | Fresh secret bytes for the selected message-digest size.
generateEntropyWith :: MessageHash -> IO BS.ByteString
generateEntropyWith = getEntropy . entropySizeWith

-- | Pure key generation; reject entropy whose length does not match the config.
keyPairFromEntropyWith :: MessageHash -> BS.ByteString -> Maybe (SecretKey, PublicKey)
keyPairFromEntropyWith config bytes
  | BS.length bytes /= entropySizeWith config = Nothing
  | otherwise = do
      values <- chunks bytes
      let sk = SecretKey values
      pure (sk, publicKey sk)
  where
    chunks bs
      | BS.null bs = Just []
      | otherwise = (:) <$> digestFromBytes (BS.take digestSize bs)
                         <*> chunks (BS.drop digestSize bs)

generateKeyPairWith :: MessageHash -> IO (SecretKey, PublicKey)
generateKeyPairWith config = do
  bytes <- generateEntropyWith config
  maybe (ioError (userError "Invalid entropy source length")) pure
    (keyPairFromEntropyWith config bytes)

-- Configurable digests are raw bytes, not the fixed SHA-256 chain Digest type.
-- No prehash is performed here. Always check the length before using zipWith.
signingDigitsWith :: MessageHash -> BS.ByteString -> Maybe [Int]
signingDigitsWith config digest = do
  if BS.length digest == messageDigestSize config then Just () else Nothing
  pure (base16Bytes digest)

-- | Sign a raw digest directly. Nothing means a digest/key size mismatch.
-- Use the secret key at most once across all entry points and configurations.
signDigestWith :: MessageHash -> SecretKey -> BS.ByteString -> Maybe Signature
signDigestWith config (SecretKey xs) digest = do
  ds <- signingDigitsWith config digest
  if length xs /= chainCountWith config then Nothing
    else Just (Signature (zipWith advance ds xs))

-- | Verify a raw digest, rejecting mismatched digest/key/signature sizes.
verifyDigestWith :: MessageHash -> PublicKey -> BS.ByteString -> Signature -> Bool
verifyDigestWith config (PublicKey pk) digest (Signature sig) =
  case signingDigitsWith config digest of
    Nothing -> False
    Just ds -> length pk == chainCountWith config && length sig == chainCountWith config &&
      zipWith advance (map (15 -) ds) sig == pk

-- | Hash once with the selected callback, validate its length, then sign.
signOnceWith :: MessageHash -> SecretKey -> BS.ByteString -> Maybe Signature
signOnceWith config sk message = hashMessage config message >>= signDigestWith config sk

-- | Hash once with the selected callback, validate its length, then verify.
verifyWith :: MessageHash -> PublicKey -> BS.ByteString -> Signature -> Bool
verifyWith config pk message sig =
  maybe False (\digest -> verifyDigestWith config pk digest sig) (hashMessage config message)
