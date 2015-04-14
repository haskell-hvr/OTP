-- |Implements HMAC-Based One-Time Password Algorithm as defined in RFC 4226 and
-- Time-Based One-Time Password Algorithm as defined in RFC 6238.
module Data.OTP
       ( hotp
       , totp
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
    let h = truncate
            $ toBytes
            $ hmacAlg alg secr
            $ runPut
            $ putWord64be cnt
    in h `mod` (10^digit)
  where
    truncate :: ByteString -> Word32
    truncate b =
        let offset = BS.last b .&. 15
            rb = BS.take 4 $ BS.drop (fromIntegral offset) b
        in case runGet getWord32le rb of
            Left e -> error e
            Right b -> shiftR b 1 -- get last 31 bits as a number


-- | Compute an TOTP using secret key and time.
totp :: (HashAlgorithm a)
     => a                       -- ^ Hash algorithm to use
     -> ByteString              -- ^ Shared secret
     -> UTCTime                 -- ^ Time of TOTP
     -> Word64                  -- ^ Time period
     -> Word                    -- ^ Number of digits in password
     -> Word32                  -- ^ TOTP
totp alg secr time period digits =
    let timePOSIX = floor $ utcTimeToPOSIXSeconds time
        timeCounter = timePOSIX `div` period
    in hotp alg secr timeCounter digits
