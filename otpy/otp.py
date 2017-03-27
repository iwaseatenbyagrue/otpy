from math import floor
from time import time
from hashlib import sha1, sha256, sha512
import hmac

from base64 import b32decode


class SeedError(Exception):
    pass


class CounterError(Exception):
    pass


def counter_to_bytes(counter_int):
    """ Takes a HOTP counter as an integer, and returns a bytearray.
    """
    return bytearray([
                    int(counter_int) >> max(0, 64 - ((x+1) * 8)) & 0xff
                    for x in range(64/8)
                    ])


def get_totp_from_b32_secret(secret, **kwargs):
    """ Get TOTP token from a base32 encoded secret.

    This is a convenience function to get a token from a 'raw' secret.
    """
    secret_bytes = b32decode(
                                secret.replace(" ", "").upper(),
                                casefold=True
                            )
    return get_totp_code(secret_bytes, **kwargs)


def get_hotp_from_b32_secret(secret, **kwargs):
    """ Get HOTP token from a base32 encoded secret.


    This is a convenience function to get a token from a 'raw' secret.
    """
    secret_bytes = b32decode(
                                secret.replace(" ", "").upper(),
                                casefold=True
                            )
    return get_hotp_code(secret_bytes, **kwargs)


def get_hotp_code(secret, count=None, algorithm=sha1, digits=6, **kwargs):
    """ Implements HOTP based on https://tools.ietf.org/html/rfc4226.

    All this call actually does is correctly prepare our HMAC.
    It then uses get_otp_code to do the rest

    """

    if count is None:
        raise CounterError('no counter provided, or counter is None')

    if isinstance(algorithm, (str, bytearray, bytes)):
        algorithm = {
                        "sha1": sha1,
                        "sha256": sha256,
                        "sha512": sha512
                    }.get(algorithm, sha1)

    return get_otp_code(
                            hmac.new(
                                secret,
                                counter_to_bytes(count),
                                algorithm
                            ).digest(),
                            int(digits)
                        )


def get_totp_code(
                    secret, timestamp=None, initial_timestamp=0,
                    period=30, algorithm=sha1, digits=6, **kwargs):
    """ Implements TOTP based on https://tools.ietf.org/html/rfc6238.

    All this call actually does is correctly prepare our HMAC.
    It then uses get_otp_code to do the rest
    """
    if isinstance(algorithm, (str, bytearray, bytes)):
        algorithm = {
                        "sha1": sha1,
                        "sha256": sha256,
                        "sha512": sha512
                    }.get(algorithm, sha1)

    if timestamp is None:
        timestamp = time()

    time_count = int(floor((
                                int(timestamp) - int(initial_timestamp)
                            ) / float(period)))

    return get_otp_code(
                        hmac.new(
                                    secret,
                                    counter_to_bytes(time_count),
                                    algorithm
                        ).digest(),
                        int(digits))


def get_otp_code(seed, digits=6):
    """ Implements the OTP token derivation algorithm.

    See https://tools.ietf.org/html/rfc4226.

    It expects a seed, a string of at least 20 raw bytes.
    For this to actually be (H|T)OTP, those bytes should be HMAC.
    It also accepts `digits`, the desired token/code length.
    """
    if len(seed) < 20:
        raise SeedError("seed must be at least 20 bytes")

    seed_bytes = bytearray(seed)

    # take last byte
    last_byte = seed_bytes[-1]

    # get our offset from the last_byte's low bits
    offset = last_byte & 0xf

    # * perform Dynamic Truncation to obtain a 4 byte string.
    #   Takes 4 consecutive bytes from the seed, starting from offset.
    # * convert our 4 byte string to a 31 bit number.
    #   Mask half of the first byte with 0x7f.
    bin_code = (seed_bytes[offset] & 0x7f) << 24 | \
        (seed_bytes[offset + 1 % len(seed)] & 0xff) << 16 | \
        (seed_bytes[offset + 2 % len(seed)] & 0xff) << 8 | \
        seed_bytes[offset + 3 % len(seed)] & 0xff

    # Clear out some cruft
    del seed_bytes
    del last_byte
    del offset

    # Get our actual OTP token
    code = str(bin_code % 10**(digits))

    del bin_code

    # the token may not be of the desired length, in which case, prepend zeros
    return "{}{}".format("0"*max(0, digits - len(code)), code)
