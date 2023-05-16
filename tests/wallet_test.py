#!/usr/bin/env python3
import append_parent_path
import os
from pawnlib.config import pawn
from pawnlib.output import is_file, open_json
from pawnlib.typing import sys_exit, str2bool, keys_exists
from iconsdk.wallet.wallet import KeyWallet
from iconsdk.wallet import wallet


def validate_wallet(keystore_filename=""):
    keystore_json = open_json(keystore_filename)
    pawn.console.debug(f"Validating wallet - {keystore_json}")
    if isinstance(keystore_json, dict):
        if keys_exists(keystore_json, "crypto", "cipher") and \
                keystore_json['crypto']['cipher'] == 'aes-128-ctr':
            pawn.console.debug("ok crypto")
        else:
            pawn.console.log("[red]cipher is wrong")
        if keys_exists(keystore_json, "crypto", "cipherparams", "iv"):
            if len(keystore_json['crypto']['cipherparams']['iv']) != 32:
                pawn.console.log(f"[red] Invalid iv in keystore len={len(keystore_json['crypto']['cipherparams']['iv'])}")
                pawn.console.log("[red] Please recreate the keystore file")
                raise ValueError("Invalid keystore")


for i in range(1, 1000):
    wallet = KeyWallet.create()
    filename = "keystore_tmp.json"
    password = 1234
    if is_file(filename):
        os.remove(filename)
    wallet.store(filename, "1234")  # throw exception if having an error.
    validate_wallet(keystore_filename=filename)
