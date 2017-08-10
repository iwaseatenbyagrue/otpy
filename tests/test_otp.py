import otpy.otp as otp
import pytest

from hashlib import sha1, sha256, sha512


def test_get_algo():
    """ Ensure get_algo returns sha1 for invalid cases.

    Ensure get_algo returns the correct algo for valid input
    """
    for h in [sha1, sha256, sha512]:
        assert h == otp.get_algo(h)

    assert sha1 == otp.get_algo('not a hash name')
    assert sha1 == otp.get_algo(1)
    assert sha1 == otp.get_algo(None)
    assert sha256 == otp.get_algo("SHA256")
    assert sha256 == otp.get_algo("sha256")


def test_get_totp_from_b32_secret():
    """ Test get_totp_from_b32_secret.

    """
    last = None

    # Check spaces work
    assert otp.get_totp_from_b32_secret("a"*16, timestamp=0) == \
        otp.get_totp_from_b32_secret("a "*16, timestamp=0)

    for x in range(3, 10):
        for algo in ['sha1', 'sha256', 'sha512']:
            current_token = otp.get_totp_from_b32_secret(
                                                            'testinginginging',
                                                            digits=x,
                                                            algorithm=algo)
            token = otp.get_totp_from_b32_secret(
                                                    'testinginginging',
                                                    digits=x,
                                                    timestamp=10000*x,
                                                    algorithm=algo)
        assert last != token
        assert current_token != token
        assert len(token) == x
        if not token.startswith('0'):
            assert str(int(token)) == token
        last = token


def test_get_hotp_from_b32_secret():
    """ Test get_hotp_from_b32_secret.
    """
    last = None

    assert otp.get_hotp_from_b32_secret("a"*16, count=0) == \
        otp.get_hotp_from_b32_secret("a "*16, count=0)

    for x in range(3, 10):
        for c in range(1, 5):
            for algo in ['sha1', 'sha256', 'sha512']:

                current_token = otp.get_totp_from_b32_secret(
                                    'testinginginging',
                                    digits=x,
                                    count=c,
                                    algorithm=algo)

                token = otp.get_hotp_from_b32_secret(
                            'testinginginging',
                            count=c,
                            timestamp=10000*x,
                            digits=x,
                            algorithm=algo)

                assert last != token
                assert current_token != token
                last = token

                assert len(token) == x
                if not token.startswith('0'):
                    assert str(int(token)) == token


def test_get_otp_code_seed_error():
    """ Ensure get_otp_code errors on insufficient seed material
    """
    for x in range(1, 20):
        with pytest.raises(otp.SeedError):
            otp.get_otp_code("a"*x)

    assert len(otp.get_otp_code("a"*20))


def test_hotp_from_b32_secret_counter_error():
    """ Ensure get_hotp_from_b32_secret errors on missing counter
    """

    with pytest.raises(otp.CounterError):
        otp.get_hotp_from_b32_secret("a"*16)
        otp.get_hotp_from_b32_secret("a"*16, count=None)

    assert otp.get_hotp_from_b32_secret("a"*16, count=1)


def test_counter_to_bytes_errors():
    """ Ensure counter_to_bytes errors on bad input
    """

    with pytest.raises(otp.CounterError):
        otp.counter_to_bytes(None)
        otp.counter_to_bytes('a')
        otp.counter_to_bytes(False)


def test_time_to_bytes_errors():
    """ Ensure counter_to_bytes errors on bad input
    """

    with pytest.raises(otp.TimeError):
        otp.time_to_bytes(None)
        otp.time_to_bytes(0, None)
        otp.time_to_bytes(0, 0, None)
        otp.time_to_bytes(0, None, 0)
        otp.time_to_bytes('a')
        otp.time_to_bytes(False)
