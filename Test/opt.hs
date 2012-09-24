module Main where

import Codec.Utils
import Data.OTP
import System.Exit (exitFailure)

hotp_test 0 = 755224
hotp_test 1 = 287082
hotp_test 2 = 359152
hotp_test 3 = 969429
hotp_test 4 = 338314
hotp_test 5 = 254676
hotp_test 6 = 287922
hotp_test 7 = 162583
hotp_test 8 = 399871
hotp_test 9 = 520489

secret_hotp :: [Octet]
secret_hotp = [49,50,51,52,53,54,55,56,57,48,49,50,51,52,53,54,55,56,57,48]

hotp_t = map (\x -> (hotp secret_hotp x 6) == (hotp_test x)) [0..9]

tests = hotp_t

main =  if (and tests) then putStrLn "Tests succeful!"
        else do
                putStrLn "Tests falls!"
                exitFailure
