module WOTSMinusTests (tests) where

import Control.Monad (forM_, unless)
import Crypto.HashBased.Hash
import qualified Crypto.HashBased.WOTSMinus as M
import qualified Crypto.HashBased.WOTSMinus.Internal as I
import Crypto.HashBased.WOTS.Internal (advance)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Bits (xor)
import Numeric (showHex)

assert :: String -> Bool -> IO ()
assert label ok = unless ok (ioError (userError ("WOTS-: " ++ label)))

require :: Maybe a -> IO a
require = maybe (ioError (userError "WOTS-: invalid test fixture")) pure

hex :: [Digest] -> String
hex = concatMap (\b -> let s = showHex b "" in replicate (2-length s) '0' ++ s)
    . BS.unpack . BS.concat . map digestBytes

tests :: IO ()
tests = do
  assert "parameters" (M.winternitzBase == 16 && M.chainCount == 64 && M.signatureSize == 2048)
  forM_ [0, 2047, 2049, 2144] $ \n ->
    assert "malformed key length" (case I.secretKeyFromBytes (BS.replicate n 0) of
      Nothing -> True
      _ -> False)
  sk <- require (I.secretKeyFromBytes (BS.pack (take 2048 (cycle [0..255]))))
  (pureSecret, purePublic) <- require (M.keyPairFromEntropy (BS.pack (take 2048 (cycle [0..255]))))
  assert "public pure generation matches fixture" (M.publicKey sk == purePublic &&
    M.signOnce sk (C8.pack "abc") == M.signOnce pureSecret (C8.pack "abc"))
  forM_ [0, M.entropySize - 1, M.entropySize + 1] $ \n ->
    assert "public entropy length rejection" (case M.keyPairFromEntropy (BS.replicate n 0) of
      Nothing -> True
      _ -> False)
  entropy <- M.generateEntropy
  assert "public entropy size" (BS.length entropy == M.entropySize && M.entropySize == 2048)
  (entropySecret, entropyPublic) <- require (M.keyPairFromEntropy entropy)
  assert "two-phase signing" (M.verify entropyPublic BS.empty (M.signOnce entropySecret BS.empty))
  let pk@(I.PublicKey endpoints) = M.publicKey sk
      message = C8.pack "abc"
      sig@(I.Signature parts) = M.signOnce sk message
  -- The independent Python WOTS oracle's first 64 chains have no checksum.
  fixture <- lines <$> readFile "test/fixtures/wots.txt"
  assert "independent checksum-free fixture" (map (take (2048*2)) fixture == [hex endpoints, hex parts])
  assert "signature verifies" (M.verify pk message sig)
  assert "digest signing matches independent message fixture" (M.signDigest sk (hash message) == sig)
  assert "digest verifies message signature" (M.verifyDigest pk (hash message) sig)
  assert "changed digest rejected for this fixture" (not (M.verifyDigest pk (hash (C8.pack "abd")) sig))
  zero <- require (digestFromBytes (BS.replicate 32 0))
  let rawSig@(I.Signature rawParts) = M.signDigest sk zero
      I.SecretKey secretParts = sk
  assert "raw digest signing does not prehash" (rawParts == secretParts)
  assert "raw digest verifies" (M.verifyDigest pk zero rawSig)
  assert "raw digest is not hashed again" (not (M.verify pk (digestBytes zero) rawSig))
  assert "changed message rejected for this fixture" (not (M.verify pk (C8.pack "abd") sig))
  other <- require (I.secretKeyFromBytes (BS.replicate 2048 42))
  assert "wrong key rejected" (not (M.verify (M.publicKey other) message sig))
  assert "digest wrong key rejected" (not (M.verifyDigest (M.publicKey other) (hash message) sig))
  forM_ [0..63] $ \position -> do
    damaged <- require (digestFromBytes (BS.map (`xor` 1) (digestBytes (parts !! position))))
    let changed = take position parts ++ [damaged] ++ drop (position+1) parts
    assert "tampering rejected" (not (M.verify pk message (I.Signature changed)))
  assert "short signature rejected" (not (M.verify pk message (I.Signature (drop 1 parts))))
  assert "long signature rejected" (not (M.verify pk message (I.Signature (hash BS.empty:parts))))
  -- Digest-level forgery: advance every node once, without using the secret key.
  -- No assertion is made that these chosen digests have known message preimages.
  low <- require (digestFromBytes (BS.replicate 32 0x11))
  high <- require (digestFromBytes (BS.replicate 32 0x22))
  let I.Signature lowParts = M.signDigest sk low
      forged = I.Signature (map (advance 1) lowParts)
  assert "original digest verifies" (M.verifyDigest pk low (I.Signature lowParts))
  assert "checksum-free digest forgery succeeds" (M.verifyDigest pk high forged)
  assert "unadvanced signature fails for changed digest" (not (M.verifyDigest pk high (I.Signature lowParts)))
  forM_ [BS.empty, C8.pack "toy WOTS-"] $ \msg -> do
    (secret, public) <- M.generateKeyPair
    assert "public API with fresh key" (M.verify public msg (M.signOnce secret msg))
