# -*- coding: utf-8 -*-
from pkg_resources import iter_entry_points
from time import time
from hashlib import sha1, sha256, sha512

import click
from click_plugins import with_plugins

from . import otp


@with_plugins(iter_entry_points('{}.plugins'.format(__package__)))
@click.group()
@click.version_option()
@click.pass_context
@click.option(
    "-a", "--algorithm", default="sha1", show_default=True,
    type=click.Choice(["md5", "sha1", "sha256", "sha512"]),
    help="Seed derivation algorithm"
)
def base(ctx, algorithm):
    """ otpy 0.1 - a simple TOTP and HOTP token generator
    """
    if ctx.obj is None:
        ctx.obj = {}
    
    ctx.obj["algorithm"] = algorithm


@base.command()
@click.argument("secret")
@click.option(
    '--digits',
    '-d',
    help='token digits',
    default=6,
    type=int
)
@click.option(
    '--timestamp',
    '-t',
    help='Timestamp (in seconds in epoch) to use',
    default=time(),
    type=int
)
@click.pass_context
def totp(ctx, secret, digits, timestamp):
    """ Returns a TOTP token given a SECRET
    """

    print otp.get_totp_from_b32_secret(
            secret, digits=digits, timestamp=timestamp,
            algorithm=ctx.obj["algorithm"]
          )


@base.command()
@click.argument("secret")
@click.option(
    '--digits',
    '-d',
    help='token digits',
    default=6,
    type=int
)
@click.option(
    '--count',
    '-c',
    help='token counter value',
    default=None,
    required=True,
    type=int
)
@click.pass_context
def hotp(ctx, secret, count, digits):
    """ Returns a HOTP token given a SECRET and COUNT.
    """

    print otp.get_hotp_from_b32_secret(
            secret, count=count, digits=digits,
            algorithm=ctx.obj["algorithm"]
          )
