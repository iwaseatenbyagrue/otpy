# -*- coding: utf-8 -*-
from pkg_resources import iter_entry_points

import click
from click_plugins import with_plugins

from . import otp

@with_plugins(iter_entry_points('{}.plugins'.format(__package__)))
@click.group()
@click.version_option()
def base():
    """ otpy 0.1 - a simple TOTP and HOTP token generator
    """
    pass

@base.command()
@click.argument("secret")
@click.option('--digits','-d',
    help='token digits',
    default=6,
    type=int
)
def totp(secret,digits):
    """ Returns a TOTP token (similar to Google Authenticator for example) given a SECRET
    """
    print otp.get_totp_from_b32_secret(secret, digits=digits)

@base.command()
@click.argument("secret")
@click.option('--digits','-d',
    help='token digits',
    default=6,
    type=int
)
@click.option('--count','-c',
    help='token counter value',
    default=None,
    required=True,
    type=int
)
def hotp(secret,count,digits):
    """ Returns a HOTP token (similar to Google Authenticator for example) given a SECRET
    """    

    print otp.get_hotp_from_b32_secret(secret, count=count, digits=digits)
    
