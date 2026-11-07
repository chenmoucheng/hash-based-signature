-- | Fixed SHA-256 boundary backed by the C implementation in cryptohash-sha256.
module Crypto.HashBased.Hash
  ( Digest, hash, digestBytes, digestFromBytes, digestSize ) where

import qualified Crypto.Hash.SHA256 as SHA256
import qualified Data.ByteString as BS

newtype Digest = Digest BS.ByteString deriving (Eq)

digestSize :: Int
digestSize = 32

hash :: BS.ByteString -> Digest
hash = Digest . SHA256.hash

digestBytes :: Digest -> BS.ByteString
digestBytes (Digest bytes) = bytes

-- | Accept exactly one SHA-256-sized value; no hashing is performed.
digestFromBytes :: BS.ByteString -> Maybe Digest
digestFromBytes bytes
  | BS.length bytes == digestSize = Just (Digest bytes)
  | otherwise = Nothing
