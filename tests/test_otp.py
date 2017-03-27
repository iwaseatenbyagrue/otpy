import otpy.otp as otp
import pytest


def test_get_totp_from_b32_secret():
    """ Test get_totp_from_b32_secret.

    """
    last = None

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
