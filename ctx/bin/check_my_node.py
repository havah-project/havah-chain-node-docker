#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import append_parent_path
import os
import argparse
from common import icon2, base, resources, typing
from pawnlib.config import pawn, pconf
from pawnlib.builder.generator import generate_banner
from pawnlib.output import is_file, PrintRichTable, open_file, write_file, write_json
from pawnlib.typing import sys_exit, str2bool, keys_exists, flatten, todaydate, Null, convert_dict_hex_to_int
from pawnlib.resource import get_hostname, get_public_ip, get_local_ip, check_port
from pawnlib.utils.icx_signer import load_wallet_key
from pawnlib.utils.http import CallHttp, get_operator_truth, append_http, NetworkInfo
from ast import literal_eval
from functools import partial
from copy import deepcopy


class CheckMyNode:
    def __init__(self, is_write_file=False):
        self._conf = pconf()
        self._env = base.get_environments()
        self._node_address = self._env.get('NODE_ADDRESS', '')
        self._owner_address = None
        self.result = {}
        self.is_write_file = is_write_file

        self._table_options = dict(
            with_idx=False,
            show_lines=True,
            columns_options=dict(
                value=dict(
                    justify='left'
                )
            )
        )
        self._local_endpoint = None
        self._public_endpoint = None
        self.set_endpoint()

    def set_endpoint(self):
        if self._env.get('LOCAL_ENDPOINT'):
            self._local_endpoint = self._env.get('LOCAL_ENDPOINT')
        else:
            _default_rpc_port = self._env.get('GOLOOP_RPC_ADDR', ":9000")
            self._local_endpoint = f"http://localhost{_default_rpc_port}"

        if self._env.get('PUBLIC_ENDPOINT'):
            self._public_endpoint = self._env.get('PUBLIC_ENDPOINT')
        else:
            self._public_endpoint = base.get_public_endpoint()

        if not self._public_endpoint:
            self._public_endpoint = self._local_endpoint

        self._local_endpoint = append_http(self._local_endpoint)
        self._public_endpoint = append_http(self._public_endpoint)

    def run(self):
        pawn.console.debug(f"Service: {self._env.get('SERVICE')}, public endpoint: {self._public_endpoint}, local endpoint: {self._local_endpoint}")
        self.check_system_information()
        self.check_environments()
        self.check_connectivity_to_seed()
        self.check_wallet()
        self.find_my_owner_key(url=self._public_endpoint)
        self.check_validator_info(self._public_endpoint)
        self.check_validator_status(self._public_endpoint)
        self.check_node_status(self._local_endpoint, kind='local')
        self.check_node_status(self._public_endpoint, kind='public')
        self.check_comparing_node_status()
        self.result['updated_date'] = todaydate('ms')

        if self.is_write_file:
            def default(obj):
                if hasattr(obj, 'to_json'):
                    return obj.to_json()
                else:
                    return str(obj)
            import json
            _result_dumps = json.dumps(dict(self.result), indent=4, default=default)
            res = write_file(f"{self._env.get('BASE_DIR')}/config/check_my_node.json", _result_dumps)
            pawn.console.log(res)

    def _print_result_decorator(func):
        def from_kwargs(self, *args, **kwargs):
            func_name = func.__name__
            title = func_name.replace('_', ' ').title()
            kind = kwargs.get('kind', '')
            result_key = func_name
            if kind:
                result_key = f"{func_name}_{kind}"
                kind = f"- {kind}"

            pawn.console.print(f"\n[bold]✅ {title} {kind}")
            pawn.console.debug(f"Start '{func_name}' function")
            ret = func(self, *args, **kwargs)
            _is_error = False
            if ret:
                if isinstance(ret, dict):
                    if ret.get('result'):
                        ret = ret.get('result')
                    elif ret.get('error'):
                        print_error_message(ret.get('error'))
                        _is_error = True

                self.result[result_key] = ret

                if func_name in ["check_node_status"]:
                    ret = [ret]

                if not _is_error:
                    table_options = deepcopy(self._table_options)
                    if func_name in ["check_validator_status"]:
                        table_options['call_value_func'] = partial(literal_eval)
                    PrintRichTable(data=ret, **table_options)

            return ret
        return from_kwargs

    @staticmethod
    def check_recommended_rules(key, value):
        recommended_rules = {
            "memory": {
                "message": "[yellow](We recommended a minimum 32GB RAM for validator)[/yellow]",
                "operator": [value, ">=", 32],
                "unit": "GB",
            }
        }
        if value and recommended_rules.get(key):
            rule = recommended_rules.get(key)
            unit = rule.get('unit', '')
            operator = rule.get('operator')
            result = get_operator_truth(*operator)

            if not result:
                return f"{value}{unit} {rule.get('message')}"
            else:
                return f"{value}{unit}"

    @_print_result_decorator
    def check_system_information(self):

        system_info = {
            "hostname": get_hostname(),
            # "public_ip": get_public_ip(),
            "public_ip": base.get_public_ip(),
            "local_ip": base.get_local_ip(),
            "platform": resources.get_platform_info(),
            "memory": self.check_recommended_rules("memory", resources.get_mem_info().get('mem_total')),
            "rlimit": resources.get_rlimit_nofile(),

        }
        return system_info

    @_print_result_decorator
    def check_connectivity_to_seed(self):
        _seed_env = self._env.get('SEEDS')
        from concurrent import futures
        from pawnlib.output import classdump

        if not _seed_env:
            print_error_message("SEEDS environment variable not set")
        else:
            _seeds = [seed.strip() for seed in _seed_env.split(',')]
            with pawn.console.status("Check seeds") as status:
                with futures.ThreadPoolExecutor(max_workers=3) as executor:
                    _results = [
                        executor.submit(self._check_port, _seed, status)
                        for _seed in _seeds
                    ]
                    results = []
                    # results = [_result.result() for _result in futures.as_completed(_results)]
                    for i, result in enumerate(futures.as_completed(_results)):
                        if not result.result().get('result'):
                            print_error_message(f"Cannot connect to {result.result().get('seed')}. Please check your outbound network or Firewall")
                        results.append(result.result())
                    return results

    @staticmethod
    def _check_port(seed=None, status=None):
        status.update(f"Trying to connect the '{seed}'")
        result = check_port(seed)
        return {"seed": seed, "result": result}

    @_print_result_decorator
    def check_wallet(self):
        conf = pconf()
        keystore_file = ""
        if conf.data.env.KEY_STORE_FILENAME:
            keystore_file = f"{conf.data.env.BASE_DIR}/config/{conf.data.env.KEY_STORE_FILENAME}"
            pawn.console.log(f"<KEY_STORE_FILENAME>, {keystore_file}")
        elif conf.data.env.GOLOOP_KEY_STORE:
            keystore_file = conf.data.env.GOLOOP_KEY_STORE
            pawn.console.log(f"<GOLOOP_KEY_STORE>, {keystore_file}")

        if is_file(keystore_file):
            pawn.console.log(f"'{keystore_file}' file exists")
        else:
            raise ValueError(f"'{keystore_file}' not found")

        _secret = open_file(conf.data.env.GOLOOP_KEY_SECRET)
        _password = conf.data.env.KEY_PASSWORD

        if not _password:
            print_error_message("'KEY_PASSWORD' environment is empty")
        if not _secret:
            pawn.console.log(f"[yellow]'{conf.data.env.GOLOOP_KEY_SECRET}' file is empty.")

        if _secret != _password:
            pawn.console.log("[red]Password and Secret are different.")
            pawn.console.debug(f"[red] {_secret} (GOLOOP_KEY_SECRET) != {_password} (KEY_PASSWORD)")
            pawn.console.log(f"[red]Sync password to {conf.data.env.GOLOOP_KEY_SECRET}")
            write_file(conf.data.env.GOLOOP_KEY_SECRET, _password)

        try:
            wallet = load_wallet_key(file_or_object=keystore_file, password=_password)
            if not self._node_address:
                self._node_address = wallet.get('address')

            if not conf.PAWN_DEBUG:
                del wallet['private_key']
                del wallet['public_key_long']

            validate_result = typing.validate_wallet(keystore_filename=keystore_file, print_error=False)
            if not validate_result.get('result'):
                print_error_message(f"{validate_result.get('reason')}. Please recreate the wallet.")

        except Exception as e:
            print_error_message(f"Failed to load wallet - {e}")
            wallet = {}
        return wallet

    @_print_result_decorator
    def find_my_owner_key(self, url):
        if self._node_address:
            res = icon2.get_validators_info(
                endpoint=url,
            )
            if isinstance(res, dict) and keys_exists(res, "result", "validators"):
                for validator in res['result']['validators']:
                    if validator.get('node') == self._node_address or validator.get('owner') == self._node_address:
                        self._owner_address = validator.get('owner')
                        pawn.console.log("Found my owner key")
                        if self._owner_address == self._node_address:
                            pawn.console.log("[yellow]Use the same [bold]node key[/bold] and [bold]owner key[/bold].")
                            node_address = self._node_address
                        else:
                            pawn.console.log("[yellow]Use the node key.")
                            node_address = f"[bold][yellow]{self._node_address}[/yellow][/bold]"

                        return {
                            "name": validator.get('name'),
                            "owner address": self._owner_address,
                            "node address": node_address,
                            "node public_key": f"[yellow]{validator.get('nodePublicKey')}[/yellow]"
                        }
        print_error_message(f"Your owner key was not found on the {self._env.get('SERVICE')}. \n"
                            f"[yellow]{self._node_address}[/yellow] is not registered as an owner or node key.")

    @_print_result_decorator
    def check_environments(self):
        _env = {
            "SERVICE": f"[bold]{pconf().data.env.SERVICE}[/bold]",
            "Public RPC endpoint": self._public_endpoint,
            "Local RPC endpoint": self._local_endpoint,
        }
        return _env

    @_print_result_decorator
    def check_validator_info(self, url=None):
        res = icon2.get_validator_info(
            endpoint=url,
            address=self._owner_address
        )
        return res

    @_print_result_decorator
    def check_validator_status(self, url=None):
        # TODO: check status with endpoint of MainNet or VegaNet
        res = icon2.get_validator_status(
            endpoint=url,
            address=self._owner_address
        )
        parsed_status = icon2.parse_abnormal_validator_status(res)
        for key, v in parsed_status.items():
            print_error_message(f"{key}={v.get('value')}, [yellow]{v.get('description')}[/yellow]")

        return res

    @_print_result_decorator
    def check_node_status(self, url=None, kind=None):
        if not check_port(url):
            print_error_message(f"Cannot connect to {url}")
        else:
            _expected_nid = ""
            if pconf().data.env.SERVICE:
                _expected_nid = base.get_expected_nid(pconf().data.env.SERVICE)

            res = CallHttp(f"{url}/admin/chain").run()
            if res.response.error:
                print_error_message(res.response.error)
                print_error_message("Your node is not running")
            else:
                nid = res.response.result[0]['nid']
                if _expected_nid and nid != _expected_nid:
                    print_error_message(f"Something went wrong. Please check your SERVICE environment or database. {nid} != {_expected_nid}")
                    pawn.console.log(f"[yellow]{pconf().data.env.SERVICE} expected nid={_expected_nid}")
                    expected_service = base.get_expected_service(nid)
                    if expected_service:
                        pawn.console.log(f"[yellow]This seems to be a database for '{expected_service}'")

                if not pconf().data.env.ONLY_GOLOOP:
                    res.response.result[0]['service'] = pconf().data.env.SERVICE
                return res.response.result[0]

        return {}

    @_print_result_decorator
    def check_comparing_node_status(self):
        local = self.result.get('check_node_status_local')
        public = self.result.get('check_node_status_public')
        if local and public:
            for k in ["cid", "nid", "channel"]:
                if local.get(k) != public.get(k):
                    pawn.console.log(f"[red][ERROR] '{k}' is different. local={local.get(k)}, public={public.get(k)}")

            pconf().data.result.diff_height = public.get('height', 0) - local.get('height', 0)
            pawn.console.log(f"Left BlockHeight: {pconf().data.result.diff_height} ({public.get('height', 0)} - {local.get('height', 0)})")
        else:
            message = ""
            if not local:
                message = "'localhost'"
            if not public:
                if message:
                    message += " and "
                message += "'public'"
            print_error_message(f"Failed to fetch state from {message} endpoint")


def print_banner():
    print(generate_banner("Check my node", description="check my node", author="jinwoo", version="0.2", font="smslant"))


def print_error_message(text=None):
    if text == "SCOREError(-30003): E0003:MethodNotFound":
        text = "It's not yet decentralized."
    pawn.console.log(f"[red]❌ {text}")


def main():
    print_banner()
    parser = argparse.ArgumentParser(prog='havah_wallet')
    parser.add_argument('-v', '--verbose', action='count', help='verbose mode ', default=0)
    parser.add_argument('-s', '--silent', action='count', help='silent mode ', default=0)
    parser.add_argument('-w', '--write', action='count', help='write mode ', default=0)
    args = parser.parse_args()

    pawn.set(
        data=dict(
            env=base.get_environments(),
            result={}
        ),
    )
    if args.silent:
        pawn.console = Null()
    if args.verbose:
        pawn.set(PAWN_DEBUG=True)

    CheckMyNode(is_write_file=str2bool(args.write)).run()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pawn.console.log("[red]\n\nKeyboardInterrupt")

