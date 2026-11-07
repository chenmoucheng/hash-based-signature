module Main (main) where

import Control.Monad (forM_, unless)
import Crypto.HashBased.Hash
import qualified Crypto.HashBased.WOTS as W
import Crypto.HashBased.WOTS.Internal
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Bits (xor)
import Data.List (foldl')
import Numeric (showHex)
import qualified WOTSMinusTests

assert :: String -> Bool -> IO ()
assert label ok = unless ok (ioError (userError label))

hex :: BS.ByteString -> String
hex = concatMap (\b -> let s = showHex b "" in replicate (2 - length s) '0' ++ s) . BS.unpack

require :: String -> Maybe a -> IO a
require label = maybe (ioError (userError label)) pure

main :: IO ()
main = do
  -- SHA-256 known answers; abc is also published in RFC 6234.
  assert "SHA256 empty" (hex (digestBytes (hash BS.empty)) ==
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  assert "SHA256 abc" (hex (digestBytes (hash (C8.pack "abc"))) ==
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  forM_ [0, 1, 31, 33, 64] $ \n ->
    assert "reject malformed digest" (digestFromBytes (BS.replicate n 0) == Nothing)
  forM_ [0, signatureSize - 1, signatureSize + 1] $ \n -> do
    let malformed = secretKeyFromBytes (BS.replicate n 0)
    assert "reject malformed internal key fixture" (case malformed of Nothing -> True; _ -> False)
  assert "parameters" (messageDigits == 64 && checksumDigits == 3 &&
    W.chainCount == 67 && W.signatureSize == 2144)
  zero <- require "zero digest" (digestFromBytes (BS.replicate digestSize 0))
  ones <- require "ones digest" (digestFromBytes (BS.replicate digestSize 255))
  assert "zero checksum 0x3c0" (signingDigits zero == replicate 64 0 ++ [3,12,0])
  assert "ones checksum padded 000" (signingDigits ones == replicate 64 15 ++ [0,0,0])
  -- Exercise all nibble positions and values, independently reconstructing bytes.
  forM_ [0..63] $ \position -> forM_ [0..15] $ \value -> do
    let bytes = BS.pack [fromIntegral (if i == position `div` 2
          then if even position then value * 16 else value else 0) | i <- [0..31]]
    digest <- require "digit fixture" (digestFromBytes bytes)
    let ds = signingDigits digest
    assert "base16 order" (take 64 ds == replicate position 0 ++ [value] ++ replicate (63-position) 0)
    assert "checksum value" (foldl' (\a b -> a * 16 + b) 0 (drop 64 ds) == 960-value)
  -- Every reachable checksum, including carries at 0x00f/0x010 and 0x0ff/0x100.
  forM_ [0..960] $ \checksum -> do
    let total = 960 - checksum
        nibbles = [max 0 (min 15 (total - 15*i)) | i <- [0..63]]
        packDigits [] = []
        packDigits (a:b:rest) = fromIntegral (a*16+b) : packDigits rest
        packDigits [_] = [] -- unreachable: exactly 64 nibbles
    digest <- require "checksum fixture" (digestFromBytes (BS.pack (packDigits nibbles)))
    let cs = drop 64 (signingDigits digest)
    assert "checksum carries and padding" (length cs == 3 &&
      cs == [checksum `div` 256, (checksum `div` 16) `mod` 16, checksum `mod` 16])
  let seed = hash (C8.pack "chain test")
  forM_ [0..15] $ \start -> forM_ [0..15-start] $ \steps ->
    assert "chain segment" (chain start steps seed == Just (iterate (hash . digestBytes) seed !! steps))
  forM_ [(-1,0), (16,0), (0,-1), (0,16), (15,1), (1,maxBound)] $ \(start,steps) ->
    assert "chain invalid bounds" (chain start steps seed == Nothing)
  let fixtureBytes = BS.pack (take signatureSize (cycle [0..255]))
  sk <- require "fixture key" (secretKeyFromBytes fixtureBytes)
  let pk@(PublicKey publicParts) = W.publicKey sk
      message = C8.pack "abc"
      sig@(Signature signatureParts) = W.signOnce sk message
  fixture <- lines <$> readFile "test/fixtures/wots.txt"
  assert "independent complete public key and signature" (fixture ==
    [hex (BS.concat (map digestBytes publicParts)), hex (BS.concat (map digestBytes signatureParts))])
  assert "fixture verifies" (W.verify pk message sig)
  assert "changed message rejected" (not (W.verify pk (C8.pack "abd") sig))
  other <- require "other fixture key" (secretKeyFromBytes (BS.replicate signatureSize 42))
  assert "different public key rejected" (not (W.verify (W.publicKey other) message sig))
  -- Mutate every signature component, including all checksum chains.
  forM_ [0..chainCount-1] $ \position -> do
    let mutate d = digestFromBytes (BS.map (`xor` 1) (digestBytes d))
    damaged <- require "mutated digest" (mutate (signatureParts !! position))
    let parts = take position signatureParts ++ [damaged] ++ drop (position+1) signatureParts
    assert "changed signature rejected" (not (W.verify pk message (Signature parts)))
  assert "truncated internal signature rejected" (not (W.verify pk message (Signature (drop 1 signatureParts))))
  assert "oversized internal signature rejected" (not (W.verify pk message (Signature (seed:signatureParts))))
  -- Public production path, with separate fresh keys for each message.
  forM_ [BS.empty, C8.pack "hello WOTS", BS.replicate 1024 255] $ \msg -> do
    (secret, public) <- W.generateKeyPair
    assert "generated key signs and verifies" (W.verify public msg (W.signOnce secret msg))
  WOTSMinusTests.tests
  putStrLn "All WOTS, WOTS-, and SHA-256 tests passed."
