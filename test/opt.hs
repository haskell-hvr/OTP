module Main where

import Crypto.Hash
import Data.ByteString  (ByteString)
import Data.OTP
import Data.Time
import Data.Word
import System.Exit      (exitFailure)
import Test.Tasty
import Test.Tasty.HUnit

import qualified Data.ByteString as BS

hotpSecret :: ByteString
hotpSecret = "12345678901234567890"

testHotp :: Word64 -> Word32 -> TestTree
testHotp key result = testCase (show result) $ do
    let h = hotp SHA1 hotpSecret key 6
    result @=? h

hotpResults :: [Word32]
hotpResults =
    [ 755224, 287082, 359152
    , 969429, 338314, 254676
    , 287922, 162583, 399871
    , 520489
    ]


-- totp_t = zipWith (\x y -> (totp secret_otp x 8 30) == y) (map (read) ["1970-01-01 00:00:59 UTC",
--         "2005-03-18 01:58:29 UTC", "2005-03-18 01:58:31 UTC", "2009-02-13 23:31:30 UTC",
--         "2033-05-18 03:33:20 UTC"])
--         [94287082, 07081804, 14050471, 89005924, 69279037]


main :: IO ()
main = defaultMain $ testGroup "unit tests"
    [ testGroup "hotp" $ map (uncurry testHotp) $ zip [0..] hotpResults ]
