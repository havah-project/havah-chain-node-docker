#!/usr/bin/env python3
from iconsdk.wallet.wallet import Wallet
from pawnlib.config import pawn
import append_parent_path
from common import base


pawn.console.log(base.get_public_ip())
pawn.console.log(base.get_local_ip())
