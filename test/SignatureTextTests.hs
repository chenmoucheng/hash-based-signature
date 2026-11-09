module SignatureTextTests (tests) where

import Control.Monad (forM_, unless)
import Crypto.HashBased.Hash (hash, digestBytes)
import Crypto.HashBased.MessageHash
import qualified Crypto.HashBased.WOTS as W
import qualified Crypto.HashBased.WOTSMinus as M
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import qualified Data.Text as T

assert :: String -> Bool -> IO ()
assert label ok = unless ok (ioError (userError ("SignatureText: " ++ label)))

require :: Maybe a -> IO a
require = maybe (ioError (userError "SignatureText: invalid fixture")) pure

check :: Eq sig => Int -> sig -> (sig -> T.Text) -> (T.Text -> Maybe sig) -> IO ()
check bytes signature encode decode = do
  let encoded = encode signature
      zero = T.replicate (bytes*2) (T.singleton '0')
  assert "round trip and expected length" (decode encoded == Just signature && T.length encoded == bytes*2)
  assert "uppercase import" (decode (T.toUpper encoded) == Just signature)
  zeros <- require (decode zero)
  assert "leading zeros preserved" (encode zeros == zero)
  allBytes <- require (decode (T.take (bytes*2) (T.concat (replicate bytes (T.pack "0123456789abcdef")))))
  assert "hex byte order and lowercase export" (T.isPrefixOf (T.pack "0123456789abcdef") (encode allBytes))
  forM_ [T.empty, T.drop 1 encoded, T.drop 2 encoded, T.snoc encoded '0',
         encoded <> T.pack "00", T.pack "0x" <> encoded, T.snoc encoded '\n',
         T.cons ' ' (T.drop 1 encoded), T.cons 'g' (T.drop 1 encoded),
         T.cons '\xff41' (T.drop 1 encoded), T.cons '\0' (T.drop 1 encoded)] $ \bad ->
    assert "malformed text rejected" (decode bad == Nothing)

tests :: IO ()
tests = do
  let message = C8.pack "abc"
      fixtureEntropy n = BS.pack (take n (cycle [0..255]))
  (sk,pk) <- require (W.keyPairFromEntropy (fixtureEntropy W.entropySize))
  (msk,mpk) <- require (M.keyPairFromEntropy (fixtureEntropy M.entropySize))
  let signature = W.signOnce sk message
      minusSignature = M.signOnce msk message
  check W.signatureSize signature W.signatureToText W.signatureFromText
  check M.signatureSize minusSignature M.signatureToText M.signatureFromText
  check W.signatureSize pk W.publicKeyToText W.publicKeyFromText
  check M.signatureSize mpk M.publicKeyToText M.publicKeyFromText
  fixture <- lines <$> readFile "test/fixtures/wots.txt"
  assert "public key export matches independent fixture" (take 1 fixture == [T.unpack (W.publicKeyToText pk)])
  assert "minus public key export matches independent fixture" (map (take (M.signatureSize*2)) (take 1 fixture) ==
    [T.unpack (M.publicKeyToText mpk)])
  assert "export matches independent fixture" (drop 1 fixture == [T.unpack (W.signatureToText signature)])
  assert "minus export matches independent fixture" (map (take (M.signatureSize*2)) (drop 1 fixture) ==
    [T.unpack (M.signatureToText minusSignature)])
  imported <- require (W.signatureFromText (W.signatureToText signature))
  minusImported <- require (M.signatureFromText (M.signatureToText minusSignature))
  importedPublic <- require (W.publicKeyFromText (W.publicKeyToText pk))
  minusImportedPublic <- require (M.publicKeyFromText (M.publicKeyToText mpk))
  assert "imported signatures and public keys verify" (W.verify importedPublic message imported &&
    M.verify minusImportedPublic message minusImported)
  -- All-zero text is structurally valid, but is not an authenticated signature.
  zeros <- require (W.signatureFromText (T.replicate (W.signatureSize*2) (T.singleton '0')))
  assert "parsing does not replace verification" (not (W.verify pk message zeros))
  forM_ [1,20,32,64] $ \size -> do
    config <- require (mkMessageHash size (\msg -> BS.take size
      (digestBytes (hash msg) <> digestBytes (hash (BS.cons 0 msg)))))
    (secret,public) <- require (W.keyPairFromEntropyWith config (fixtureEntropy (W.entropySizeWith config)))
    (minusSecret,minusPublic) <- require (M.keyPairFromEntropyWith config (fixtureEntropy (M.entropySizeWith config)))
    sig <- require (W.signOnceWith config secret message)
    msig <- require (M.signOnceWith config minusSecret message)
    check (W.signatureSizeWith config) sig W.signatureToText (W.signatureFromTextWith config)
    check (M.signatureSizeWith config) msig M.signatureToText (M.signatureFromTextWith config)
    check (W.signatureSizeWith config) public W.publicKeyToText (W.publicKeyFromTextWith config)
    check (M.signatureSizeWith config) minusPublic M.publicKeyToText (M.publicKeyFromTextWith config)
    parsed <- require (W.signatureFromTextWith config (W.signatureToText sig))
    mparsed <- require (M.signatureFromTextWith config (M.signatureToText msig))
    parsedPublic <- require (W.publicKeyFromTextWith config (W.publicKeyToText public))
    mparsedPublic <- require (M.publicKeyFromTextWith config (M.publicKeyToText minusPublic))
    assert "configured imported signatures and keys verify" (W.verifyWith config parsedPublic message parsed &&
      M.verifyWith config mparsedPublic message mparsed)
    assert "wrong scheme public key length rejected" (W.publicKeyFromTextWith config (M.publicKeyToText minusPublic) == Nothing &&
      M.publicKeyFromTextWith config (W.publicKeyToText public) == Nothing)
    assert "wrong scheme length rejected" (W.signatureFromTextWith config (M.signatureToText msig) == Nothing &&
      M.signatureFromTextWith config (W.signatureToText sig) == Nothing)
    if size /= 32 then assert "default config rejects custom length" (
      W.signatureFromText (W.signatureToText sig) == Nothing &&
      M.signatureFromText (M.signatureToText msig) == Nothing &&
      W.publicKeyFromText (W.publicKeyToText public) == Nothing &&
      M.publicKeyFromText (M.publicKeyToText minusPublic) == Nothing) else pure ()
