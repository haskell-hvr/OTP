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
