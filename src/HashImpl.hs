{-# LANGUAGE CPP #-}

-- | SPDX-License-Identifier: MIT
--
-- @since 0.1.0.0
module HashImpl where

#if defined(MIN_VERSION_SHA)
import qualified Data.ByteString.Lazy as BS.L
import qualified Data.Digest.Pure.SHA as SHA
#else
import qualified Crypto.Hash.SHA1     as SHA1
import qualified Crypto.Hash.SHA256   as SHA256
import qualified Crypto.Hash.SHA512   as SHA512
#endif

import qualified Data.ByteString      as BS


-- | Shared secret encoded as raw octets
type Secret = BS.ByteString

-- | Hash algorithm used for HOTP\/TOTP computations
data HashAlgorithm = SHA1
                   | SHA256
                   | SHA512
                   deriving (Eq,Show)

hmac :: HashAlgorithm -> Secret -> BS.ByteString -> BS.ByteString
hmac alg key msg = case alg of
#if defined(MIN_VERSION_SHA)
    SHA1   -> BS.L.toStrict (SHA.bytestringDigest (SHA.hmacSha1   (BS.L.fromStrict key) (BS.L.fromStrict msg)))
    SHA256 -> BS.L.toStrict (SHA.bytestringDigest (SHA.hmacSha256 (BS.L.fromStrict key) (BS.L.fromStrict msg)))
    SHA512 -> BS.L.toStrict (SHA.bytestringDigest (SHA.hmacSha512 (BS.L.fromStrict key) (BS.L.fromStrict msg)))
#else
    SHA1   -> SHA1.hmac   key msg
    SHA256 -> SHA256.hmac key msg
    SHA512 -> SHA512.hmac key msg
#endif
