module Main (main) where

import qualified Data.ByteString.Char8 as BS
import Crypto.HashBased.WOTS

main :: IO ()
main = do
  (secret, public) <- generateKeyPair
  let message = BS.pack "hello WOTS"
      signature = signOnce secret message -- Never use secret again.
  print (verify public message signature)
