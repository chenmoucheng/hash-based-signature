-- | Private implementation and deterministic test seams. Not a public API.
module Crypto.HashBased.WOTS.Internal where

import Crypto.HashBased.Hash
import Crypto.HashBased.MessageHash
import qualified Data.ByteString as BS
import System.Entropy (getEntropy)

newtype SecretKey = SecretKey [Digest]
newtype PublicKey = PublicKey [Digest] deriving (Eq)
newtype Signature = Signature [Digest] deriving (Eq)

-- Fixed base-16 WOTS: 64 message digits and 3 checksum digits.
winternitzBase, messageDigits, checksumDigits, chainCount, signatureSize :: Int
winternitzBase = 16
messageDigits = digestSize * 2
checksumDigits = length (digitsOf (messageDigits * (winternitzBase - 1)))
chainCount = messageDigits + checksumDigits
signatureSize = chainCount * digestSize

-- Most significant digit first; zero has one digit.
digitsOf :: Int -> [Int]
digitsOf n
  | n < winternitzBase = [n]
  | otherwise = digitsOf (n `div` winternitzBase) ++ [n `mod` winternitzBase]

base16 :: Digest -> [Int]
base16 = base16Bytes . digestBytes

base16Bytes :: BS.ByteString -> [Int]
base16Bytes = concatMap (\b -> let n = fromIntegral b in [n `div` 16, n `mod` 16])
       . BS.unpack

signingDigits :: Digest -> [Int]
signingDigits digest = ds ++ replicate (checksumDigits - length cs) 0 ++ cs
  where
    ds = base16 digest
    cs = digitsOf (sum (map (winternitzBase - 1 -) ds))

-- Internal callers supply validated counts. No input-dependent list indexing.
advance :: Int -> Digest -> Digest
advance steps value
  | steps <= 0 = value
  | otherwise = advance (steps - 1) (hash (digestBytes value))

-- | Checked chain segment; start is a position, not a hash input/domain tag.
chain :: Int -> Int -> Digest -> Maybe Digest
chain start steps value
  | start < 0 || start > top || steps < 0 || steps > top - start = Nothing
  | otherwise = Just (advance steps value)
  where top = winternitzBase - 1

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
    Nothing -> ioError (userError "WOTS: entropy source returned an invalid length")
    Just pair -> pure pair

publicKey :: SecretKey -> PublicKey
publicKey (SecretKey xs) = PublicKey (map (advance (winternitzBase - 1)) xs)

-- | Sign a supplied digest directly, without hashing it again.
-- Use this secret key at most once across ALL signing entry points.
signDigest :: SecretKey -> Digest -> Signature
signDigest (SecretKey xs) digest =
  Signature (zipWith advance (signingDigits digest) xs)

-- | Verify a supplied digest directly, without hashing it again.
verifyDigest :: PublicKey -> Digest -> Signature -> Bool
verifyDigest (PublicKey pk) digest (Signature sig) =
  length pk == chainCount && length sig == chainCount &&
  zipWith advance remaining sig == pk
  where remaining = map (winternitzBase - 1 -) (signingDigits digest)

-- | Hash the message once, then sign. Single use is not enforced by the type.
signOnce :: SecretKey -> BS.ByteString -> Signature
signOnce sk = signDigest sk . hash

-- | Hash the message once, then verify.
verify :: PublicKey -> BS.ByteString -> Signature -> Bool
verify pk message = verifyDigest pk (hash message)

-- | Number of chains for the selected message hash. Chain nodes remain SHA-256.
chainCountWith :: MessageHash -> Int
chainCountWith config = 2 * messageDigestSize config + length (digitsOf (2 * messageDigestSize config * 15))

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
  let ds = base16Bytes digest
      cs = digitsOf (sum (map (15 -) ds))
      width = chainCountWith config - 2 * messageDigestSize config
  pure (ds ++ replicate (width - length cs) 0 ++ cs)

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
