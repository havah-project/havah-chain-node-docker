#!/usr/bin/env python3
from iconsdk.wallet.wallet import Wallet
from pawnlib.config import pawn
import append_parent_path
from common import icon2


wallet_loader = icon2.WalletLoader(
    filename="/test.json",
    password="test",
    keysecret_filename="/secret",
    force_sync=True,
    default_path="",
    debug=True,
    is_logging=False
)


wallet_loader.create_wallet()

pawn.console.log(wallet_loader.get_public_key())
