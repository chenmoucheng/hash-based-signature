-- | Private implementation and deterministic test seams. Not a public API.
module Crypto.HashBased.WOTS.Internal where

import Crypto.HashBased.Hash
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
base16 = concatMap (\b -> let n = fromIntegral b in [n `div` 16, n `mod` 16])
       . BS.unpack . digestBytes

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

-- Test seam only: production key generation always uses operating-system entropy.
secretKeyFromBytes :: BS.ByteString -> Maybe SecretKey
secretKeyFromBytes bytes
  | BS.length bytes /= signatureSize = Nothing
  | otherwise = SecretKey <$> chunks bytes
  where
    chunks bs
      | BS.null bs = Just []
      | otherwise = (:) <$> digestFromBytes (BS.take digestSize bs)
                         <*> chunks (BS.drop digestSize bs)

generateKeyPair :: IO (SecretKey, PublicKey)
generateKeyPair = do
  bytes <- getEntropy signatureSize
  case secretKeyFromBytes bytes of
    Nothing -> ioError (userError "WOTS: entropy source returned an invalid length")
    Just sk -> pure (sk, publicKey sk)

publicKey :: SecretKey -> PublicKey
publicKey (SecretKey xs) = PublicKey (map (advance (winternitzBase - 1)) xs)

-- | Sign at most ONE message with this key. Values do not enforce single use.
signOnce :: SecretKey -> BS.ByteString -> Signature
signOnce (SecretKey xs) message =
  Signature (zipWith advance (signingDigits (hash message)) xs)

verify :: PublicKey -> BS.ByteString -> Signature -> Bool
verify (PublicKey pk) message (Signature sig) =
  length pk == chainCount && length sig == chainCount &&
  zipWith advance remaining sig == pk
  where remaining = map (winternitzBase - 1 -) (signingDigits (hash message))
