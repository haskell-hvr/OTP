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
import qualified Data.ByteString.Char8 as BC

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


testTotp :: (ByteString, UTCTime, SomeAlg, Word32) -> TestTree
testTotp (secr, key, alg', result) =
    testCase (show alg' ++ " => " ++ show result) $ case alg' of
        SomeAlg alg -> do
            let t = totp alg secr key 30 8
            result @=? t

sha1Secr   = BC.pack $ take 20 $ cycle "12345678901234567890"
sha256Secr = BC.pack $ take 32 $ cycle "12345678901234567890"
sha512Secr = BC.pack $ take 64 $ cycle "12345678901234567890"

totpData :: [(ByteString, UTCTime, SomeAlg, Word32)]
totpData =
    [ (sha1Secr,   read "1970-01-01 00:00:59 UTC", SomeAlg SHA1,   94287082)
    , (sha256Secr, read "1970-01-01 00:00:59 UTC", SomeAlg SHA256, 46119246)
    , (sha512Secr, read "1970-01-01 00:00:59 UTC", SomeAlg SHA512, 90693936)
    , (sha1Secr,   read "2005-03-18 01:58:29 UTC", SomeAlg SHA1,   07081804)
    , (sha256Secr, read "2005-03-18 01:58:29 UTC", SomeAlg SHA256, 68084774)
    , (sha512Secr, read "2005-03-18 01:58:29 UTC", SomeAlg SHA512, 25091201)
    , (sha1Secr,   read "2005-03-18 01:58:31 UTC", SomeAlg SHA1,   14050471)
    , (sha256Secr, read "2005-03-18 01:58:31 UTC", SomeAlg SHA256, 67062674)
    , (sha512Secr, read "2005-03-18 01:58:31 UTC", SomeAlg SHA512, 99943326)
    , (sha1Secr,   read "2009-02-13 23:31:30 UTC", SomeAlg SHA1,   89005924)
    , (sha256Secr, read "2009-02-13 23:31:30 UTC", SomeAlg SHA256, 91819424)
    , (sha512Secr, read "2009-02-13 23:31:30 UTC", SomeAlg SHA512, 93441116)
    , (sha1Secr,   read "2033-05-18 03:33:20 UTC", SomeAlg SHA1,   69279037)
    , (sha256Secr, read "2033-05-18 03:33:20 UTC", SomeAlg SHA256, 90698825)
    , (sha512Secr, read "2033-05-18 03:33:20 UTC", SomeAlg SHA512, 38618901)
    , (sha1Secr,   read "2603-10-11 11:33:20 UTC", SomeAlg SHA1,   65353130)
    , (sha256Secr, read "2603-10-11 11:33:20 UTC", SomeAlg SHA256, 77737706)
    , (sha512Secr, read "2603-10-11 11:33:20 UTC", SomeAlg SHA512, 47863826)
    ]


main :: IO ()
main = defaultMain $ testGroup "unit tests"
    [ testGroup "hotp" $ map (uncurry testHotp) $ zip [0..] hotpResults
    , testGroup "totp" $ map testTotp totpData
    ]
