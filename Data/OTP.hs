-- |Implements HMAC-Based One-Time Password Algorithm as defined in RFC 4226 and
-- Time-Based One-Time Password Algorithm as defined in RFC 6238.
module Data.OTP (hotp, totp) where

import Codec.Utils
import Data.Bits
import Data.HMAC
import Data.Time.Clock
import Data.Time.Clock.POSIX

-- | Compute an HOTP using secret key and counter value.
hotp
    :: [Octet]  -- ^ Secret key
    -> Int      -- ^ Counter value
    -> Int      -- ^ Number of digits in password
    -> Int      -- ^ HOTP
hotp key count digit' = truncate_hotp (hmac_sha1 key count') digit'
    where truncate_hotp hmac_result digit' = snum `mod` (10 ^ digit')
            where snum  = fromTwosComp sbits
                  sbits = dt hmac_result
                  dt hmac_r = [(head p) .&. 0x7F] ++ (tail p)
                      where offsetBits = (hmacr !! 19) .&. 0xF
                            offset = fromTwosComp [offsetBits]
                            p = take 4 (drop offset hmacr)
                            hmacr = pad hmac_r
                                where pad xs = if length xs < 20 then pad (0 : xs) else xs
          count' = pad (toTwosComp count)
              where pad xs = if length xs < 8 then pad (0 : xs) else xs

-- | Compute an TOTP using secret key and time.
totp
    :: [Octet]  -- ^ Secret key
    -> UTCTime  -- ^ Time
    -> Int      -- ^ Number of digits in password
    -> Int      -- ^ Period
    -> Int      -- ^ TOTP
totp key time digit' period = hotp key timeCounter digit'
    where timePOSIX = utcTimeToPOSIXSeconds time
          timeCounter = (floor timePOSIX) `div` period