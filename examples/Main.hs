module Main (main) where

import qualified Data.ByteString.Char8 as BS
import Crypto.HashBased.WOTS

main :: IO ()
main = do
  bytes <- generateEntropy
  (secret, public) <- maybe (fail "Invalid entropy length") pure (keyPairFromEntropy bytes)
  let message = BS.pack "hello WOTS"
      signature = signOnce secret message -- Never use secret again.
  print (verify public message signature)
