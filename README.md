# `OTP`: HMAC-Based and Time-Based One-Time Passwords (HOTP & TOTP)  [![Hackage](https://img.shields.io/hackage/v/OTP.svg)](https://hackage.haskell.org/package/OTP) [![Haskell CI](https://github.com/haskell-hvr/OTP/actions/workflows/haskell.yml/badge.svg)](https://github.com/haskell-hvr/OTP/actions/workflows/haskell.yml)

**Please refer to the [package description](https://hackage.haskell.org/package/OTP#description) for an overview of `OTP`.**

## Usage examples

### Generating one-time passwords

If you need to generate HOTP password described in RFC4226, then use

```haskell
>>> hotp SHA1 "1234" 100 6
317569

>>> hotp SHA512 "1234" 100 6
134131
```

Or

```haskell
>>> totp SHA1 "1234" (read "2010-10-10 00:01:00 UTC") 30 8
43388892
```

to generate TOTP password described in RFC6238.

### Checking one-time passwords

```haskell
hotpCheck :: HashAlgorithm      -- ^ Hashing algorithm
          -> Secret             -- ^ Shared secret
          -> (Word8, Word8)     -- ^ how much counters to take lower and higher than ideal
          -> Word64             -- ^ ideal (expected) counter value
          -> Word8              -- ^ Number of digits in password
          -> Word32             -- ^ Password entered by user
          -> Bool               -- ^ True if password acceptable
```

```haskell
>>> hotpCheck SHA1 "1234" (0,0) 10 6 50897
True

>>> hotpCheck SHA1 "1234" (0,0) 9 6 50897
False

>>> hotpCheck SHA1 "1234" (0,1) 9 6 50897
True
```

Here almost the same aguments as for `hotp` function, but there is
also `(0, 0)` tuple. This tuple describes range of counters to check
in case of desynchronisation of counters between client and
server. I.e. if you specify `(1, 1)` and ideal counter will be `10`
then function will check passwords for `[9, 10, 11]` list of
counters.

Here is the same for TOTP:

```haskell
>>> totpCheck SHA1 "1234" (0, 0) (read "2010-10-10 00:00:00 UTC") 30 6 778374
True

>>> totpCheck SHA1 "1234" (0, 0) (read "2010-10-10 00:00:30 UTC") 30 6 778374
False

>>> totpCheck SHA1 "1234" (1, 0) (read "2010-10-10 00:00:30 UTC") 30 6 778374
True
```
