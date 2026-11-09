-- | Shared hexadecimal encoding of ordered digest values. No algorithm metadata.
module Crypto.HashBased.Internal.DigestText (encodeDigests, decodeDigests) where

import Crypto.HashBased.Hash
import qualified Data.ByteString as BS
import Data.Char (ord)
import qualified Data.Text as T
import Numeric (showHex)

encodeDigests :: [Digest] -> T.Text
encodeDigests = T.pack . concatMap byteHex . BS.unpack . BS.concat . map digestBytes
  where byteHex byte = let value = showHex byte "" in replicate (2 - length value) '0' ++ value

-- Check the exact character count before decoding. Integer arithmetic avoids
-- overflowing when the selected configuration has a very large payload size.
decodeDigests :: Int -> T.Text -> Maybe [Digest]
decodeDigests count input
  | toInteger (T.length input) /= toInteger count * toInteger digestSize * 2 = Nothing
  | otherwise = decodeHex (T.unpack input) >>= chunks . BS.pack
  where
    decodeHex [] = Just []
    decodeHex (a:b:rest) = do
      high <- nibble a
      low <- nibble b
      ((fromIntegral (16 * high + low)) :) <$> decodeHex rest
    decodeHex [_] = Nothing
    nibble c
      | c >= '0' && c <= '9' = Just (ord c - ord '0')
      | c >= 'a' && c <= 'f' = Just (ord c - ord 'a' + 10)
      | c >= 'A' && c <= 'F' = Just (ord c - ord 'A' + 10)
      | otherwise = Nothing
    chunks bytes
      | BS.null bytes = Just []
      | otherwise = (:) <$> digestFromBytes (BS.take digestSize bytes)
                         <*> chunks (BS.drop digestSize bytes)
