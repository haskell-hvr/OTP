-- |Implements HMAC-Based One-Time Password Algorithm as defined in RFC 4226 and
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
import Data.Bits
import Data.Byteable
import Data.ByteString       (ByteString)
import Data.Serialize.Get
import Data.Serialize.Put
import Data.Time.Clock
import Data.Time.Clock.POSIX
import Data.Word

import qualified Data.ByteString as BS


-- | Compute an HOTP using secret key and counter value.
hotp :: (HashAlgorithm a)
     => a                       -- ^ Hashing algorithm from module "Crypto.Hash"
     -> ByteString              -- ^ Shared secret
     -> Word64                  -- ^ Counter value
     -> Word                    -- ^ Number of digits in password
     -> Word32                  -- ^ HOTP
hotp alg secr cnt digit =
    let h = trunc
            $ toBytes
            $ hmacAlg alg secr
            $ runPut
            $ putWord64be cnt
    in h `mod` (10^digit)
  where
    trunc :: ByteString -> Word32
    trunc b =
        let offset = BS.last b .&. 15 -- take low 4 bits of last byte
            rb = BS.take 4
                 $ BS.drop (fromIntegral offset) b -- resulting 4 byte value
        in case runGet getWord32be rb of
            Left e -> error e
            Right res -> res .&. (0x80000000 - 1) -- reset highest bit

hotpCheck :: (HashAlgorithm a)
          => a                  -- ^ Hashing algorithm
          -> ByteString         -- ^ Shared secret
          -> (Word64, Word64)   -- ^ how much counters to take lower and higher than ideal
          -> Word64             -- ^ ideal (expected) counter value
          -> Word               -- ^ Number of digits in password
          -> Word32             -- ^ Password entered by user
          -> Bool               -- ^ True if password acceptable
hotpCheck alg secr rng cnt digits pass =
    let counters = counterRange rng cnt
        passwds = map (\c -> hotp alg secr c digits) counters
    in any (pass ==) passwds

-- | Compute an TOTP using secret key and time.
totp :: (HashAlgorithm a)
     => a                       -- ^ Hash algorithm to use
     -> ByteString              -- ^ Shared secret
     -> UTCTime                 -- ^ Time of TOTP
     -> Word64                  -- ^ Time period in seconds
     -> Word                    -- ^ Number of digits in password
     -> Word32                  -- ^ TOTP
totp alg secr time period digits =
    hotp alg secr (totpCounter time period) digits

totpCheck :: (HashAlgorithm a)
          => a                  -- ^ Hashing algorithm
          -> ByteString         -- ^ Shared secret
          -> (Word64, Word64)   -- ^ How much counters to take lower and higher than ideal
          -> UTCTime            -- ^ Time of totp
          -> Word64             -- ^ Time period in seconds
          -> Word               -- ^ Numer of digits in password
          -> Word32             -- ^ Password given by user
          -> Bool               -- ^ True if password acceptable
totpCheck alg secr rng time period digits pass =
    let counters = totpCounterRange rng time period
        passwds = map (\c -> hotp alg secr c digits) counters
    in any (pass ==) passwds


-- | Calculate counter for `hotp` using time
totpCounter :: UTCTime          -- ^ Time of totp
            -> Word64           -- ^ Time period in seconds
            -> Word64           -- ^ Resulting counter
totpCounter time period =
    let timePOSIX = floor $ utcTimeToPOSIXSeconds time
    in timePOSIX `div` period

-- | Return sequence of acceptable counters. It protects you from
-- arithmetic overflow and truncates output to 1000 values, because
-- huge counter ranges are not secure.
counterRange :: (Word64, Word64) -- ^ How much counters to take lower than ideal and higher
             -> Word64           -- ^ Ideal counter value
             -> [Word64]
counterRange (tolow, tohigh) ideal =
    let l = trim 0 ideal (ideal - tolow)
        h = trim ideal maxBound (ideal + tohigh)
    in take 1000 [l..h]
  where
    trim l h = max l . min h

totpCounterRange :: (Word64, Word64)
                 -> UTCTime
                 -> Word64
                 -> [Word64]
totpCounterRange rng time period =
    counterRange rng $ totpCounter time period
