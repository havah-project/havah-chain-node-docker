from pawnlib.config import pawn
from pawnlib.output import open_json
from pawnlib.typing import keys_exists


def validate_wallet(keystore_filename="", print_error=True) -> dict:
    keystore_json = open_json(keystore_filename)
    pawn.console.debug(f"Validating wallet - {keystore_json}")
    if isinstance(keystore_json, dict):
        if keys_exists(keystore_json, "crypto", "cipher") and \
                keystore_json['crypto']['cipher'] == 'aes-128-ctr':
            pawn.console.debug("ok crypto")
        else:
            if print_error:
                pawn.console.log("[red]cipher is wrong")
            return {
                "result": False,
                "reason": "Invalid cipher"
            }

        if keys_exists(keystore_json, "crypto", "cipherparams", "iv"):
            if len(keystore_json['crypto']['cipherparams']['iv']) != 32:
                if print_error:
                    pawn.console.log(f"[red]Invalid iv in keystore len={len(keystore_json['crypto']['cipherparams']['iv'])}, {keystore_filename}")
                    pawn.console.log("[red]Please recreate the keystore file")
                return {
                    "result": False,
                    "reason": f"Invalid iv in keystore len={len(keystore_json['crypto']['cipherparams']['iv'])}"
                }

    return {
        "result": True,
        "reason": "ok"
    }
