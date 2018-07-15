-- | SPDX-License-Identifier: MIT
--
-- Implements HMAC-Based One-Time Password Algorithm as defined in RFC 4226 and
-- Time-Based One-Time Password Algorithm as defined in RFC 6238.
module Data.OTP
       ( -- * HOTP
         hotp
       , hotpCheck
         -- * TOTP
       , totp
       , totpCheck
         -- * Auxiliary
       , totpCounter
       , counterRange
       , totpCounterRange
       ) where

import Crypto.Hash
import Crypto.MAC.HMAC
import Data.Bits
import Data.ByteArray (unpack, ByteArrayAccess)
import Data.Serialize.Get
import Data.Serialize.Put
import Data.Time
import Data.Time.Clock.POSIX
import Data.Word

import qualified Data.ByteString as BS

{- | Compute HMAC-Based One-Time Password using secret key and counter value.

>>> hotp SHA1 "1234" 100 6
317569

>>> hotp SHA512 "1234" 100 6
134131

>>> hotp SHA512 "1234" 100 8
55134131

-}

hotp
  :: forall a key
   . (HashAlgorithm a, ByteArrayAccess key)
  => a                       -- ^ Hashing algorithm from module "Crypto.Hash.IO"
  -> key                     -- ^ Shared secret
  -> Word64                  -- ^ Counter value
  -> Word                    -- ^ Number of digits in a password
  -> Word32                  -- ^ HOTP
hotp _ key cnt digits =
  let msg = runPut $ putWord64be cnt
      h :: HMAC a
      h = hmac key msg
      w = trunc $ unpack h
  in w `mod` (10 ^ digits)
  where
    trunc :: [Word8] -> Word32
    trunc b =
      let offset = last b .&. 15 -- take low 4 bits of last byte
          rb = BS.pack $ take 4 $ drop (fromIntegral offset) b -- resulting 4 byte value
      in case runGet getWord32be rb of
      Left e    -> error e
      Right res -> res .&. (0x80000000 - 1) -- reset highest bit

{- | Check presented password against a valid range.

>>> hotp SHA1 "1234" 10 6
50897

>>> hotpCheck SHA1 "1234" (0,0) 10 6 50897
True

>>> hotpCheck SHA1 "1234" (0,0) 9 6 50897
False

>>> hotpCheck SHA1 "1234" (0,1) 9 6 50897
True

>>> hotpCheck SHA1 "1234" (1,0) 11 6 50897
True

>>> hotpCheck SHA1 "1234" (2,2) 8 6 50897
True

>>> hotpCheck SHA1 "1234" (2,2) 7 6 50897
False

>>> hotpCheck SHA1 "1234" (2,2) 12 6 50897
True

>>> hotpCheck SHA1 "1234" (2,2) 13 6 50897
False

-}

hotpCheck
  :: (HashAlgorithm a, ByteArrayAccess key)
  => a                  -- ^ Hashing algorithm
  -> key                -- ^ Shared secret
  -> (Word64, Word64)   -- ^ Valid counter range, before and after ideal
  -> Word64             -- ^ Ideal (expected) counter value
  -> Word               -- ^ Number of digits in a password
  -> Word32             -- ^ Password entered by user
  -> Bool               -- ^ True if password is valid
hotpCheck alg secr rng cnt len pass =
    let counters = counterRange rng cnt
        passwds = map (\c -> hotp alg secr c len) counters
    in any (pass ==) passwds

{- | Compute a Time-Based One-Time Password using secret key and time.

>>> totp SHA1 "1234" (read "2010-10-10 00:01:00 UTC") 30 6
388892

>>> totp SHA1 "1234" (read "2010-10-10 00:01:00 UTC") 30 8
43388892

>>> totp SHA1 "1234" (read "2010-10-10 00:01:15 UTC") 30 8
43388892

>>> totp SHA1 "1234" (read "2010-10-10 00:01:31 UTC") 30 8
39110359

-}

totp
  :: (HashAlgorithm a, ByteArrayAccess key)
  => a         -- ^ Hash algorithm to use
  -> key       -- ^ Shared secret
  -> UTCTime   -- ^ Time of TOTP
  -> Word64    -- ^ Time range in seconds
  -> Word      -- ^ Number of digits in a password
  -> Word32    -- ^ TOTP
totp alg secr time period len =
    hotp alg secr (totpCounter time period) len

{- | Check presented password against time periods.

>>> totp SHA1 "1234" (read "2010-10-10 00:00:00 UTC") 30 6
778374

>>> totpCheck SHA1 "1234" (0, 0) (read "2010-10-10 00:00:00 UTC") 30 6 778374
True

>>> totpCheck SHA1 "1234" (0, 0) (read "2010-10-10 00:00:30 UTC") 30 6 778374
False

>>> totpCheck SHA1 "1234" (1, 0) (read "2010-10-10 00:00:30 UTC") 30 6 778374
True

>>> totpCheck SHA1 "1234" (1, 0) (read "2010-10-10 00:01:00 UTC") 30 6 778374
False

>>> totpCheck SHA1 "1234" (2, 0) (read "2010-10-10 00:01:00 UTC") 30 6 778374
True
-}

totpCheck
  :: (HashAlgorithm a, ByteArrayAccess key)
  => a                  -- ^ Hashing algorithm
  -> key                -- ^ Shared secret
  -> (Word64, Word64)   -- ^ Valid counter range, before and after ideal
  -> UTCTime            -- ^ Time of TOTP
  -> Word64             -- ^ Time range in seconds
  -> Word               -- ^ Numer of digits in a password
  -> Word32             -- ^ Password given by user
  -> Bool               -- ^ True if password is valid
totpCheck alg secr rng time period len pass =
    let counters = totpCounterRange rng time period
        passwds = map (\c -> hotp alg secr c len) counters
    in any (pass ==) passwds


{- | Calculate HOTP counter using time. Starting time (T0
according to RFC6238) is 0 (begining of UNIX epoch)

>>> totpCounter (read "2010-10-10 00:00:00 UTC") 30
42888960

>>> totpCounter (read "2010-10-10 00:00:30 UTC") 30
42888961

>>> totpCounter (read "2010-10-10 00:01:00 UTC") 30
42888962

-}

totpCounter
  :: UTCTime     -- ^ Time of totp
  -> Word64      -- ^ Time range in seconds
  -> Word64      -- ^ Resulting counter
totpCounter time period =
    let timePOSIX = floor $ utcTimeToPOSIXSeconds time
    in timePOSIX `div` period

{- | Make a sequence of acceptable counters, protected from
arithmetic overflow. Maximum range is limited to 1000 due to huge
counter ranges being insecure.

>>> counterRange (0, 0) 9000
[9000]

>>> counterRange (1, 0) 9000
[8999,9000]

>>> length $ counterRange (5000, 0) 9000
501

>>> length $ counterRange (5000, 5000) 9000
1000

>>> counterRange (2, 2) maxBound
[18446744073709551613,18446744073709551614,18446744073709551615]

>>> counterRange (2, 2) minBound
[0,1,2]

>>> counterRange (2, 2) (maxBound `div` 2)
[9223372036854775805,9223372036854775806,9223372036854775807,9223372036854775808,9223372036854775809]

>>> counterRange (5, 5) 9000
[8995,8996,8997,8998,8999,9000,9001,9002,9003,9004,9005]

RFC recommends avoiding excessively large values for counter ranges.
-}

counterRange
  :: (Word64, Word64) -- ^ Number of counters before and after ideal
  -> Word64           -- ^ Ideal counter value
  -> [Word64]
counterRange (tolow', tohigh') ideal =
    let tolow = min 500 tolow'
        tohigh = min 499 tohigh'
        l = trim 0 ideal (ideal - tolow)
        h = trim ideal maxBound (ideal + tohigh)
    in [l..h]
  where
    trim l h = max l . min h

{- | Make a sequence of acceptable periods.

>>> totpCounterRange (0, 0) (read "2010-10-10 00:01:00 UTC") 30
[42888962]

>>> totpCounterRange (2, 0) (read "2010-10-10 00:01:00 UTC") 30
[42888960,42888961,42888962]

>>> totpCounterRange (0, 2) (read "2010-10-10 00:01:00 UTC") 30
[42888962,42888963,42888964]

>>> totpCounterRange (2, 2) (read "2010-10-10 00:01:00 UTC") 30
[42888960,42888961,42888962,42888963,42888964]

-}

totpCounterRange :: (Word64, Word64)
                 -> UTCTime
                 -> Word64
                 -> [Word64]
totpCounterRange rng time period =
    counterRange rng $ totpCounter time period
