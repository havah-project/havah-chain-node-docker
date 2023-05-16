#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import append_parent_path
from common import icon2, base, typing
from pawnlib.config import pawn
from pawnlib.input import PromptWithArgument
from pawnlib.builder.generator import generate_banner
from pawnlib.output import is_file
from pawnlib.typing import sys_exit, str2bool, keys_exists
from rich.prompt import Confirm
import argparse
import sys
import os


def get_environments():
    environment_defaults = {
        "BASE_DIR": "/goloop",
        "GOLOOP_KEY_SECRET": "/goloop/config/keysecret",
    }
    env_dict = {}
    for key, default_value in environment_defaults.items():
        env_dict[key] = os.getenv(key, default_value)
    return env_dict


def print_banner():
    print(generate_banner("wallet", author="jinwoo", version="0.1"))


def main():
    parser = argparse.ArgumentParser(prog='havah_wallet')
    parser.add_argument('command', choices=["create", "get", "convert"])
    parser.add_argument('-p', '--password', type=str, help='keystore password', default=None)
    parser.add_argument('-f', '--filename', type=str, help='keystore filename', default=None)
    parser.add_argument('-v', '--verbose', action='count', help='verbose mode ', default=0)
    parser.add_argument('-fs', '--force-sync', metavar='True/False', type=str2bool,
                        help='Synchronize password and keysecret ', default=False)

    args = parser.parse_args()

    if args.verbose > 0:
        debug = True
        pawn.console.log(f"\nArguments = {args}")
    else:
        debug = False

    pawn.set(
        data=dict(
            args=args
        ),
        PAWN_DEBUG=debug
    )
    print_banner()

    config_dict = get_environments()
    config_dir = f"{config_dict.get('BASE_DIR', '/goloop')}/config"
    keysecret_filename = config_dict.get('GOLOOP_KEY_SECRET', '/goloop/config/keysecret')

    pawn.console.log(f"It will be [bold]{args.command}[/bold] wallet")

    key_store_filename = os.getenv('KEY_STORE_FILENAME', "keystore.json")
    if not key_store_filename:
        pawn.console.log(f"[yellow]'KEY_STORE_FILENAME'[/yellow] environment variable is not defined. {key_store_filename}")
        key_store_filename = "keystore.json"

    if not args.filename:
        PromptWithArgument(
            message="Enter a filename for wallet:",
            default=f"{config_dir}/{key_store_filename}",
            invalid_message="Requires at least one character.",
            argument="filename",
            validate=lambda result: len(result) >= 1,
        ).prompt()

    if args.command == "create" and is_file(args.filename):
        print(f"Already have wallet , - {args.filename}")
        answer = Confirm.ask(prompt=f"Overwrite already existing '{args.filename}' file?", default=False)
        if not answer:
            sys_exit(message=f"Stopped. Answer={answer}")

    if not args.password:
        PromptWithArgument(
            message="Enter password for wallet",
            type="password",
            default="",
            argument="password",
            invalid_message="Requires at least one character.",
            validate=lambda result: len(result) >= 1,
        ).prompt()

    dirname, file_name = os.path.split(args.filename)

    if base.is_docker() and dirname == "":
        config_dir = f"{config_dict.get('BASE_DIR', '/goloop')}/config"
        keystore_filename = f"{config_dir}/{args.filename}"
    else:
        config_dir = None
        keystore_filename = args.filename

    if args.command != "create" and not is_file(keystore_filename):
        pawn.console.log(f"[red]File not found, {keystore_filename}")
        sys.exit(127)

    wallet_loader = icon2.WalletLoader(
        filename=args.filename,
        password=args.password,
        keysecret_filename=keysecret_filename,
        force_sync=args.force_sync,
        default_path=config_dir,
        debug=debug,
        is_logging=False
    )

    if args.command == "create":
        wallet_loader.create_wallet(force=True)
        typing.validate_wallet(args.filename)

    elif args.command == "get":
        pawn.console.log("Load Keystore file")
        typing.validate_wallet(args.filename)
        _wallet = wallet_loader.get_wallet()
        pawn.console.debug(f"Address: {_wallet.get_address()}")
        pawn.console.debug(f"Public Key: {wallet_loader.get_public_key()}")
        pawn.console.debug(f"Private Key: {_wallet.get_private_key()}")
        pawn.console.debug(f"Password: {args.password}")

    elif args.command == "convert":
        pawn.console.log("Convert file")
        wallet = wallet_loader.convert_keystore()
        if wallet:
            print(wallet.get_address())


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pawn.console.log("[red]\n\nKeyboardInterrupt")
