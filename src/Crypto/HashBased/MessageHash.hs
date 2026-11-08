-- | Caller-selected fixed-output message hashing, independent of the chain hash.
module Crypto.HashBased.MessageHash
  ( MessageHash, mkMessageHash, sha256MessageHash
  , messageDigestSize, hashMessage
  ) where

import qualified Crypto.HashBased.Hash as Chain
import qualified Data.ByteString as BS

-- Constructor hidden: positive size and representable scheme sizes are required.
data MessageHash = MessageHash Int (BS.ByteString -> BS.ByteString)

-- | Size is in bytes. Reject nonpositive sizes and sizes whose WOTS key payload
-- would overflow Int. This cannot check cryptographic quality or function purity.
mkMessageHash :: Int -> (BS.ByteString -> BS.ByteString) -> Maybe MessageHash
mkMessageHash size function
  | size <= 0 || chains * toInteger Chain.digestSize > toInteger (maxBound :: Int) = Nothing
  | otherwise = Just (MessageHash size function)
  where
    digits = 2 * toInteger size
    chains = digits + width (15 * digits)
    width n | n < 16 = 1
            | otherwise = 1 + width (n `div` 16)

sha256MessageHash :: MessageHash
sha256MessageHash = MessageHash Chain.digestSize (Chain.digestBytes . Chain.hash)

messageDigestSize :: MessageHash -> Int
messageDigestSize (MessageHash size _) = size

-- | Invoke the callback once and reject output of the wrong length.
-- Exceptions or nontermination in a caller callback are not caught.
hashMessage :: MessageHash -> BS.ByteString -> Maybe BS.ByteString
hashMessage (MessageHash size function) message
  | BS.length digest == size = Just digest
  | otherwise = Nothing
  where digest = function message
