{-# LANGUAGE OverloadedStrings #-}

module Main where

import           Data.ByteString       (ByteString)
import qualified Data.ByteString.Char8 as BC
import           Data.Time
import           Data.Word
import           Test.Tasty
import           Test.Tasty.HUnit

-- IUT
import           Data.OTP


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


testTotp :: (ByteString, UTCTime, HashAlgorithm, Word32) -> TestTree
testTotp (secr, key, alg, result) =
    testCase (show alg ++ " => " ++ show result) $ do
            let t = totp alg secr key 30 8
            result @=? t

sha1Secr :: ByteString
sha1Secr   = BC.pack $ take 20 $ cycle "12345678901234567890"

sha256Secr :: ByteString
sha256Secr = BC.pack $ take 32 $ cycle "12345678901234567890"

sha512Secr :: ByteString
sha512Secr = BC.pack $ take 64 $ cycle "12345678901234567890"

totpData :: [(ByteString, UTCTime, HashAlgorithm, Word32)]
totpData =
    [ (sha1Secr,   read "1970-01-01 00:00:59 UTC", SHA1,   94287082)
    , (sha256Secr, read "1970-01-01 00:00:59 UTC", SHA256, 46119246)
    , (sha512Secr, read "1970-01-01 00:00:59 UTC", SHA512, 90693936)
    , (sha1Secr,   read "2005-03-18 01:58:29 UTC", SHA1,   07081804)
    , (sha256Secr, read "2005-03-18 01:58:29 UTC", SHA256, 68084774)
    , (sha512Secr, read "2005-03-18 01:58:29 UTC", SHA512, 25091201)
    , (sha1Secr,   read "2005-03-18 01:58:31 UTC", SHA1,   14050471)
    , (sha256Secr, read "2005-03-18 01:58:31 UTC", SHA256, 67062674)
    , (sha512Secr, read "2005-03-18 01:58:31 UTC", SHA512, 99943326)
    , (sha1Secr,   read "2009-02-13 23:31:30 UTC", SHA1,   89005924)
    , (sha256Secr, read "2009-02-13 23:31:30 UTC", SHA256, 91819424)
    , (sha512Secr, read "2009-02-13 23:31:30 UTC", SHA512, 93441116)
    , (sha1Secr,   read "2033-05-18 03:33:20 UTC", SHA1,   69279037)
    , (sha256Secr, read "2033-05-18 03:33:20 UTC", SHA256, 90698825)
    , (sha512Secr, read "2033-05-18 03:33:20 UTC", SHA512, 38618901)
    , (sha1Secr,   read "2603-10-11 11:33:20 UTC", SHA1,   65353130)
    , (sha256Secr, read "2603-10-11 11:33:20 UTC", SHA256, 77737706)
    , (sha512Secr, read "2603-10-11 11:33:20 UTC", SHA512, 47863826)
    ]


main :: IO ()
main = defaultMain $ testGroup "test vectors"
    [ testGroup "hotp" $ map (uncurry testHotp) $ zip [0..] hotpResults
    , testGroup "totp" $ map testTotp totpData
    ]
