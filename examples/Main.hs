module Main (main) where

import qualified Data.ByteString.Char8 as BS
import Crypto.HashBased.WOTS
import Crypto.HashBased.Hash (hash)

main :: IO ()
main = do
  bytes <- generateEntropy
  (secret, public) <- maybe (fail "Invalid entropy length") pure (keyPairFromEntropy bytes)
  let message = BS.pack "hello WOTS"
      digest = hash message
      signature = signDigest secret digest -- Never use secret again.
  print (verifyDigest public digest signature)
