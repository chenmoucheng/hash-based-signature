module Main (main) where

import qualified Data.ByteString.Char8 as BS
import qualified Data.Text.IO as Text
import Crypto.HashBased.WOTS
import Crypto.HashBased.Hash (digestBytes, hash)
import Crypto.HashBased.MessageHash (hashMessage, mkMessageHash)

-- An example caller-supplied hash: SHA-256 truncated to 20 bytes.
-- Replace this function and its declared size together to use another hash.
userHash :: BS.ByteString -> BS.ByteString
userHash = BS.take userDigestSize . digestBytes . hash

userDigestSize :: Int
userDigestSize = 20 -- bytes, not bits

main :: IO ()
main = do
  config <- maybe (fail "Invalid digest size") pure (mkMessageHash userDigestSize userHash)
  -- The configured digest size determines entropy, key, and signature sizes.
  bytes <- generateEntropyWith config
  (secret, public) <- maybe (fail "Invalid entropy length") pure (keyPairFromEntropyWith config bytes)
  let message = BS.pack "hello WOTS"
  digest <- maybe (fail "Hash returned the wrong size") pure (hashMessage config message)
  signature <- maybe (fail "Digest/key size mismatch") pure (signDigestWith config secret digest)
  -- Never use secret again, including through any other signing entry point.
  let exported = signatureToText signature
  Text.putStrLn exported
  imported <- maybe (fail "Invalid signature text") pure (signatureFromTextWith config exported)
  print (verifyDigestWith config public digest imported)
  -- The message-level wrapper uses the same hash configuration.
  print (verifyWith config public message imported)
