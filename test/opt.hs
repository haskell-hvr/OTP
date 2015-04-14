module Main where

import Crypto.Hash
import Data.ByteString (ByteString)
import Data.OTP
import Data.Time
import System.Exit     (exitFailure)

import qualified Data.ByteString as BS

secret_otp :: ByteString
secret_otp = BS.pack
    [49,50,51,52,53,54,55,56,57,48,49,50,51,52,53,54,55,56,57,48]

hotp_t = zipWith (\x y -> (hotp SHA1 secret_otp x 6) == y) [0..9]
        [755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489]

-- totp_t = zipWith (\x y -> (totp secret_otp x 8 30) == y) (map (read) ["1970-01-01 00:00:59 UTC",
--         "2005-03-18 01:58:29 UTC", "2005-03-18 01:58:31 UTC", "2009-02-13 23:31:30 UTC",
--         "2033-05-18 03:33:20 UTC"])
--         [94287082, 07081804, 14050471, 89005924, 69279037]

tests = hotp_t -- ++ totp_t

main =  if (and tests) then putStrLn "Tests succeful!"
        else do
                putStrLn "Tests falls!"
                exitFailure
