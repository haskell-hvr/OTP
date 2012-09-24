-- |Implements HMAC-Based One-Time Password Algorithm as defined in RFC 4226.
module Data.OTP (hotp) where

import Codec.Utils
import Data.Bits
import Data.HMAC

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