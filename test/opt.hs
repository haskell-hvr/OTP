module Main where

import Control.Arrow
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


data SomeAlg = forall a. (HashAlgorithm a, Show a) => SomeAlg { getAlg :: a }

instance Show SomeAlg where
    show (SomeAlg a) = show a


testTotp :: (UTCTime, SomeAlg, Word32) -> TestTree
testTotp (key, alg', result) =
    testCase (show alg' ++ " => " ++ show result)
    $ case alg' of
          SomeAlg alg -> do
              let t = totp alg hotpSecret key 30 8
              result @=? t

totpData :: [(UTCTime, SomeAlg, Word32)]
totpData =
    [ (read "1970-01-01 00:00:59 UTC", SomeAlg SHA1, 94287082)
    , (read "1970-01-01 00:00:59 UTC", SomeAlg SHA256, 46119246)
    , (read "1970-01-01 00:00:59 UTC", SomeAlg SHA512, 90693936)
    ]

  -- |  1111111109 |  2005-03-18  | 00000000023523EC | 07081804 |  SHA1  |
  -- |             |   01:58:29   |                  |          |        |
  -- |  1111111109 |  2005-03-18  | 00000000023523EC | 68084774 | SHA256 |
  -- |             |   01:58:29   |                  |          |        |
  -- |  1111111109 |  2005-03-18  | 00000000023523EC | 25091201 | SHA512 |
  -- |             |   01:58:29   |                  |          |        |
  -- |  1111111111 |  2005-03-18  | 00000000023523ED | 14050471 |  SHA1  |
  -- |             |   01:58:31   |                  |          |        |
  -- |  1111111111 |  2005-03-18  | 00000000023523ED | 67062674 | SHA256 |
  -- |             |   01:58:31   |                  |          |        |
  -- |  1111111111 |  2005-03-18  | 00000000023523ED | 99943326 | SHA512 |
  -- |             |   01:58:31   |                  |          |        |
  -- |  1234567890 |  2009-02-13  | 000000000273EF07 | 89005924 |  SHA1  |
  -- |             |   23:31:30   |                  |          |        |
  -- |  1234567890 |  2009-02-13  | 000000000273EF07 | 91819424 | SHA256 |
  -- |             |   23:31:30   |                  |          |        |
  -- |  1234567890 |  2009-02-13  | 000000000273EF07 | 93441116 | SHA512 |
  -- |             |   23:31:30   |                  |          |        |
  -- |  2000000000 |  2033-05-18  | 0000000003F940AA | 69279037 |  SHA1  |
  -- |             |   03:33:20   |                  |          |        |
  -- |  2000000000 |  2033-05-18  | 0000000003F940AA | 90698825 | SHA256 |
  -- |             |   03:33:20   |                  |          |        |
  -- |  2000000000 |  2033-05-18  | 0000000003F940AA | 38618901 | SHA512 |
  -- |             |   03:33:20   |                  |          |        |
  -- | 20000000000 |  2603-10-11  | 0000000027BC86AA | 65353130 |  SHA1  |
  -- |             |   11:33:20   |                  |          |        |
  -- | 20000000000 |  2603-10-11  | 0000000027BC86AA | 77737706 | SHA256 |
  -- |             |   11:33:20   |                  |          |        |
  -- | 20000000000 |  2603-10-11  | 0000000027BC86AA | 47863826 | SHA512 |


main :: IO ()
main = defaultMain $ testGroup "unit tests"
    [ testGroup "hotp" $ map (uncurry testHotp) $ zip [0..] hotpResults
    , testGroup "totp" $ map testTotp totpData
    ]
