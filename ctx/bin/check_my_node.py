#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import append_parent_path
from common import icon2, base, resources
from pawnlib.config import pawn, pconf
from pawnlib.input import PromptWithArgument
from pawnlib.builder.generator import generate_banner
from pawnlib.output import is_file, PrintRichTable, open_file
from pawnlib.typing import sys_exit, str2bool
from rich.prompt import Confirm
import argparse
import sys
import os

from pawnlib.resource import get_hostname, get_public_ip, get_local_ip
from pawnlib.utils.icx_signer import load_wallet_key
from pawnlib.utils.http import CallHttp
from ast import literal_eval


def get_endpoint():
    default_endpoints = {
        "mainnet": "https://ctz.havah.io",
        "vega": "https://ctz.vega.havah.io",
    }

    if pconf().data.ENDPOINT:
        return pconf().data.ENDPOINT
    elif default_endpoints.get(pconf().data.SERVICE.lower()):
        return default_endpoints[pconf().data.SERVICE.lower()]
    else:
        raise ValueError("Unknown endpoint")


def get_environments():
    environment_defaults = {
        "BASE_DIR": "/goloop",
        "GOLOOP_KEY_SECRET": "/goloop/config/keysecret",
        "KEY_STORE_FILENAME": "",
        "GOLOOP_KEY_STORE": "",
        "KEY_PASSWORD": '',
        "GOLOOP_RPC_ADDR": ":9000",
        "SERVICE": "MainNet",
        "ONLY_GOLOOP": False,
        "ENDPOINT": "",
    }
    env_dict = {}
    for key, default_value in environment_defaults.items():
        if key == "SERVICE" and default_value:
            default_value = default_value.lower()
        elif key == "ONLY_GOLOOP":
            default_value = str2bool(default_value)

        env_dict[key] = os.getenv(key, default_value)
    return env_dict


def print_banner():
    print(generate_banner("Check my node", author="jinwoo", version="0.1", font="starwars"))


def main():
    print_banner()
    parser = argparse.ArgumentParser(prog='havah_wallet')
    parser.add_argument('-v', '--verbose', action='count', help='verbose mode ', default=0)
    args = parser.parse_args()

    pawn.set(
        data=get_environments(),
        columns_options=dict(
            value=dict(
                justify='left'
            )
        )
    )
    if args.verbose:
        pawn.set(PAWN_DEBUG=True)

    rpc_localhost = f"http://localhost{pconf().data.GOLOOP_RPC_ADDR}"
    check_system_information()
    pawn.console.rule("Check Environments")
    check_wallet()
    check_validator_status(url=get_endpoint())
    check_validator_info(url=get_endpoint())
    check_node_status(url=rpc_localhost)
    check_node_status(url=get_endpoint())


def check_system_information():
    pawn.console.rule("Check System information")
    columns = {
        "hostname": get_hostname(),
        "public_ip": get_public_ip(),
        "local_ip": get_local_ip(),
        "platform": resources.get_platform_info(),
        "memory": f"{resources.get_mem_info().get('mem_total')}GB",
        "rlimit": resources.get_rlimit_nofile(),

    }
    PrintRichTable(data=columns, with_idx=False, show_lines=True, columns_options=pawn.get('columns_options'))


def check_wallet():
    pawn.console.rule("Check Wallet")
    conf = pconf()
    keystore_file = ""
    if conf.data.KEY_STORE_FILENAME:
        keystore_file = f"{conf.data.BASE_DIR}/config/{conf.data.KEY_STORE_FILENAME}"
        pawn.console.log(f"<KEY_STORE_FILENAME>, {keystore_file}")
    elif conf.data.GOLOOP_KEY_STORE:
        keystore_file = conf.data.GOLOOP_KEY_STORE
        pawn.console.log(f"<GOLOOP_KEY_STORE>, {keystore_file}")

    if not is_file(keystore_file):
        raise ValueError(f"'{keystore_file}' not found")

    _secret = open_file(conf.data.GOLOOP_KEY_SECRET)
    _password = conf.data.KEY_PASSWORD

    if _secret != _password:
        pawn.console.log("[red]The passwords are different.")
        pawn.console.debug(f"[red] {_secret} (GOLOOP_KEY_SECRET) != {_password} (KEY_PASSWORD)")

    wallet = load_wallet_key(file_or_object=keystore_file, password=_password)

    pawn.set(validator_address=wallet.get('address'))

    if not conf.PAWN_DEBUG:
        del wallet['private_key']
        del wallet['public_key_long']
    PrintRichTable(data=wallet, with_idx=False, show_lines=True, columns_options=pawn.get('columns_options'))


def check_node_status(url=None):
    pawn.console.rule("Check Node Status")
    res = CallHttp(f"{url}/admin/chain").run()
    if res.response.error:
        pawn.console.log(f"[red]{res.response.error}")
    else:
        if not pconf().data.ONLY_GOLOOP:
            res.response.result[0]['service'] = pconf().data.SERVICE

        PrintRichTable(data=res.response.result, with_idx=False, show_lines=True, columns_options=pawn.get('columns_options'))


def check_validator_info(url=None):
    pawn.console.rule("Check Validator Information")
    res = icon2.get_validator_info(
        endpoint=url,
        address=pconf().validator_address
    )
    if res.get('error'):
        pawn.console.log(f"[red]{res.get('error')}")
    else:
        PrintRichTable(data=res.get('result'), with_idx=False, show_lines=True, columns_options=pawn.get('columns_options'))


def check_validator_status(url=None):
    # TODO: check status with endpoint of MainNet or VegaNet
    pawn.console.rule("Check Validator Status")
    res = icon2.get_validator_status(
        endpoint=url,
        address=pconf().validator_address
    )
    if res.get('error'):
        pawn.console.log(f"[red]{res.get('error')}")
    else:
        PrintRichTable(data=res.get('result'), with_idx=False, show_lines=True, call_value_func=literal_eval, columns_options=pawn.get('columns_options'))


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pawn.console.log("[red]\n\nKeyboardInterrupt")
