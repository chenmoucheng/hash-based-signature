module MessageHashTests (tests) where

import Control.Monad (forM_, unless)
import Crypto.HashBased.Hash
import Crypto.HashBased.MessageHash
import qualified Crypto.HashBased.WOTS as W
import qualified Crypto.HashBased.WOTS.Internal as WI
import qualified Crypto.HashBased.WOTSMinus as M
import qualified Crypto.HashBased.WOTSMinus.Internal as MI
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Numeric (showHex)

assert :: String -> Bool -> IO ()
assert label ok = unless ok (ioError (userError ("MessageHash: " ++ label)))

require :: Maybe a -> IO a
require = maybe (ioError (userError "MessageHash: invalid test fixture")) pure

isNothing :: Maybe a -> Bool
isNothing Nothing = True
isNothing _ = False

hex :: [Digest] -> String
hex = concatMap (\b -> let s = showHex b "" in replicate (2-length s) '0' ++ s)
    . BS.unpack . BS.concat . map digestBytes

tests :: IO ()
tests = do
  forM_ [minBound, -1, 0, maxBound] $ \n ->
    assert "invalid/overflowing size rejected" (isNothing (mkMessageHash n id))
  forM_ [(1,4,2), (8,18,16), (9,21,18), (16,35,32), (32,67,64), (64,131,128)] $ \(size,wc,mc) -> do
    -- Test callbacks only: truncation/concatenation is not a recommended hash.
    let callback input = BS.take size (digestBytes (hash input) <> digestBytes (hash (BS.cons 0 input)))
        msg = C8.pack "abc"
        raw = callback msg
    config <- require (mkMessageHash size callback)
    assert "derived chain counts and sizes" (W.chainCountWith config == wc &&
      M.chainCountWith config == mc && W.entropySizeWith config == wc*32 &&
      M.signatureSizeWith config == mc*32)
    assert "custom callback output" (hashMessage config msg == Just raw)
    zeroDigits <- require (WI.signingDigitsWith config (BS.replicate size 0))
    onesDigits <- require (WI.signingDigitsWith config (BS.replicate size 255))
    assert "size-dependent checksum maximum and padding" (
      length zeroDigits == wc && foldl (\a b -> 16*a+b) 0 (drop mc zeroDigits) == 15*mc &&
      onesDigits == replicate mc 15 ++ replicate (wc-mc) 0)
    let bytes = BS.pack (take (wc*32) (cycle [0..255]))
    (sk,pk) <- require (W.keyPairFromEntropyWith config bytes)
    (msk,mpk) <- require (M.keyPairFromEntropyWith config (BS.take (mc*32) bytes))
    wsig <- require (W.signOnceWith config sk msg)
    msig <- require (M.signOnceWith config msk msg)
    assert "message/digest agreement" (W.signDigestWith config sk raw == Just wsig &&
      M.signDigestWith config msk raw == Just msig && W.verifyDigestWith config pk raw wsig &&
      M.verifyDigestWith config mpk raw msig && W.verifyWith config pk msg wsig &&
      M.verifyWith config mpk msg msig)
    forM_ [BS.empty, BS.take (size-1) raw, BS.snoc raw 0] $ \bad ->
      assert "wrong digest lengths rejected" (isNothing (W.signDigestWith config sk bad) &&
        isNothing (M.signDigestWith config msk bad) && not (W.verifyDigestWith config pk bad wsig) &&
        not (M.verifyDigestWith config mpk bad msig))
    assert "wrong entropy length rejected" (isNothing (W.keyPairFromEntropyWith config (BS.snoc bytes 0)))
    -- Callbacks that lie about their output size must never silently truncate.
    forM_ [BS.empty, BS.replicate (size+1) 0] $ \bad -> do
      broken <- require (mkMessageHash size (const bad))
      assert "bad hash output rejected" (isNothing (hashMessage broken msg) &&
        isNothing (W.signOnceWith broken sk msg) && isNothing (M.signOnceWith broken msk msg) &&
        not (W.verifyWith broken pk msg wsig) && not (M.verifyWith broken mpk msg msig))
    if size == 1 then do
      fixture <- lines <$> readFile "test/fixtures/wots-1-byte.txt"
      let WI.PublicKey publicParts = pk
          WI.Signature sigParts = wsig
          MI.PublicKey minusPublicParts = mpk
          MI.Signature minusSigParts = msig
      assert "independent 1-byte checksum fixture" (fixture == [hex publicParts, hex sigParts])
      assert "independent 1-byte no-checksum fixture" (map (take (mc*64)) fixture ==
        [hex minusPublicParts, hex minusSigParts])
      -- A digest-level call must not execute the configured hash callback.
      noHash <- require (mkMessageHash size (error "unexpected prehash"))
      assert "digest API bypasses callback" (W.signDigestWith noHash sk raw == Just wsig &&
        M.signDigestWith noHash msk raw == Just msig && W.verifyDigestWith noHash pk raw wsig &&
        M.verifyDigestWith noHash mpk raw msig)
    else pure ()
  let msg = C8.pack "abc"
  (sk,pk) <- W.generateKeyPair
  (msk,mpk) <- M.generateKeyPair
  assert "default SHA256 compatibility" (W.signOnceWith sha256MessageHash sk msg == Just (W.signOnce sk msg) &&
    M.signOnceWith sha256MessageHash msk msg == Just (M.signOnce msk msg))
  short <- require (mkMessageHash 1 (BS.take 1 . digestBytes . hash))
  assert "key configuration mismatch rejected" (isNothing (W.signOnceWith short sk msg) &&
    isNothing (M.signOnceWith short msk msg) &&
    not (W.verifyWith short pk msg (W.signOnce sk msg)) && not (M.verifyWith short mpk msg (M.signOnce msk msg)))
  entropy <- W.generateEntropyWith short
  minusEntropy <- M.generateEntropyWith short
  assert "configured entropy length" (BS.length entropy == W.entropySizeWith short &&
    BS.length minusEntropy == M.entropySizeWith short)
  (customSecret,customPublic) <- W.generateKeyPairWith short
  customSig <- require (W.signOnceWith short customSecret BS.empty)
  assert "configured IO keygen" (W.verifyWith short customPublic BS.empty customSig)
  (minusSecret,minusPublic) <- M.generateKeyPairWith short
  minusSig <- require (M.signOnceWith short minusSecret BS.empty)
  assert "configured minus IO keygen" (M.verifyWith short minusPublic BS.empty minusSig)
