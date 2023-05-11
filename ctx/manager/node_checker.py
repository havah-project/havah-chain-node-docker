#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import os
import socket
import asyncio
import requests
import subprocess
import socket_request

from concurrent import futures
from datetime import datetime
from ping3 import ping

from config.configure import Configure as CFG
from common.output import send_slack, open_json
from common.icon2 import call_chain_score, get_validator_status, get_validator_info, get_validators_info
from pawnlib.utils import append_http
from pawnlib.config import pawn
from pawnlib.typing import convert_dict_hex_to_int, dict_to_line, ErrorCounter, keys_exists
from common.base import get_public_endpoint
from copy import deepcopy

from pawnlib.config import pawn, pconf


class NodeChecker:
    def __init__(self, use_file=True):
        self.cfg = CFG(use_file=use_file)
        self.config = self.cfg.config
        self._base_url = ""
        self._my_wallet_address = ""
        self.initialize()
        self.oc = OSChecker()
        self.pc = PeerChecker()

        pawn.set(
            is_avail_node_status=False,
            last_endpoint=""
        )

        self.validator_checker = ValidatorChecker(
            owner_address=self._my_wallet_address,
            cfg=self.cfg,
            public_endpoint=get_public_endpoint(),
            local_endpoint=self._local_rpc
        )
        self.unix_socket = self.config.get("GOLOOP_NODE_SOCK", "/goloop/data/cli.sock")
        self.ctl = socket_request.ControlChain(unix_socket=self.unix_socket)
        self.cfg.logger = self.cfg.get_logger('health.log')

    def _parse_environment(self):
        self._node_ip = self.get_environment_with_default('NODE_IP', 'localhost')
        self._stack_limit = int(self.config.get('CHECK_STACK_LIMIT', 360))
        self._p2p_port = int(self.config.get('GOLOOP_P2P_LISTEN', '8080').split(':')[-1])
        self._rpc_port = int(self.config.get('GOLOOP_RPC_ADDR', '9000').split(':')[-1])

        self._check_peer_stack = int(self.config.get('CHECK_PEER_STACK', 6))
        self._check_block_stack = int(self.config.get('CHECK_BLOCK_STACK', 10))
        self._check_interval = int(self.config.get('CHECK_INTERVAL', 10))
        self._check_timeout = int(self.config.get('CHECK_TIMEOUT', 10))
        self._stack_limit = int(self.config.get('CHECK_STACK_LIMIT', 360))

        self._endpoint_path = '/admin/chain/icon_dex'
        self._local_rpc = f"http://{self._node_ip}:{self._rpc_port}"
        self._endpoint = f"{self._local_rpc}{self._endpoint_path}"
        self._node_address = os.environ.get('NODE_ADDRESS', '')

    @staticmethod
    def get_environment_with_default(key="", default=""):
        env_value = os.environ.get(key, "__NOT_DEFINED__")
        if not env_value or env_value == "" or env_value == "__NOT_DEFINED__":
            return default
        if env_value != "__NOT_DEFINED__":
            return os.environ.get(key)

    def get_my_address(self):
        try:
            keystore_file = open_json(self.cfg.get_base_config('GOLOOP_KEY_STORE'))
            self._my_wallet_address = keystore_file.get("address")
        except Exception as e:
            self.cfg.logger.error(f"[ERROR] Load keystore - {e}")
            self._my_wallet_address = None

        return self._my_wallet_address

    def get_peer_goloop(self, peer_info):
        temp_dict = dict()
        temp_dict['cid'] = peer_info.get('cid', None)
        temp_dict['nid'] = peer_info.get('nid', None)
        temp_dict['height'] = peer_info.get('height', None)
        temp_dict['channel'] = peer_info.get('channel', None)
        temp_dict['state'] = peer_info.get('state', None)
        return temp_dict

    def result_formatter(self, log: str):
        return_str = f"[{datetime.today().strftime('%Y-%m-%d %H:%M:%S')}] {log}"
        return return_str

    def check_up_seeds(self, _p2p_port: int, _rpc_port: int):
        p2p_rs = list()
        rpc_rs = list()
        peer_ip_list = [addr.split(':')[0] for addr in self.config.get('SEEDS').split(',')]
        with futures.ThreadPoolExecutor() as executor:
            p2p_results = [
                executor.submit(self.oc.port, friend.split(':')[0], _p2p_port)
                for friend in peer_ip_list
            ]
            rpc_results = [
                executor.submit(self.oc.port, friend.split(':')[0], _rpc_port)
                for friend in peer_ip_list
            ]
        for i, f in enumerate(futures.as_completed(p2p_results)):
            if f.result() is False:
                p2p_rs.append(peer_ip_list[i])
        for i, f in enumerate(futures.as_completed(rpc_results)):
            if f.result() is False:
                rpc_rs.append(peer_ip_list[i])
        return p2p_rs, rpc_rs

    def get_local_rpc_endpoint(self, path=""):
        return append_http(f"{self._node_ip}:{self._rpc_port}{path}")

    def initialize(self):
        self._parse_environment()
        self._base_url = self.get_local_rpc_endpoint()

        if self._node_address:
            self._my_wallet_address = self._node_address
        else:
            self.get_my_address()

    async def check_node(self):

        self.cfg.logger.info(f"Starting check node. interval={self._check_interval}, url={self._endpoint}, timeout={self._check_timeout}")
        _block = [0, 0]
        _peer_stack = 0
        _block_stack = 0
        _error_counter = ErrorCounter(increase_index=0.5, max_consecutive_count=1000)
        while True:
            peer_rs = self.pc.peer_status(self._endpoint, timeout=self._check_timeout)
            _on_error = False

            _logging_message = ""
            if not peer_rs:
                _peer_stack += 1
                if not _peer_stack % self._check_peer_stack:
                    _logging_message = f"Node API=Failed, stack_count={_peer_stack}, Time={int(_peer_stack) * self._check_peer_stack} sec)"
                    self.cfg.logger.error(_logging_message)
                    if _error_counter.push_hit():
                        _on_error = True
                        self.cfg.send_auto_slack(
                            msg_text=_logging_message,
                            title='Node health',
                            msg_level='error'
                        )
            else:
                self.cfg.logger.info(f"Node API response: {dict_to_line(self.get_peer_goloop(peer_rs), end_separator=', ')}")
                if _peer_stack >= self._check_peer_stack:
                    _logging_message = f"Node API=OK, stack_count={_peer_stack}, Time={int(_peer_stack) * self._check_peer_stack} sec)"
                    self.cfg.logger.info(_logging_message)
                    if _error_counter.push_hit():
                        _on_error = True
                        self.cfg.send_auto_slack(
                            msg_text=_logging_message,
                            title='Node health',
                            msg_level='info'
                        )
                _peer_stack = 0
                _block[-1] = peer_rs.get('height', 0)
                if _block[-1] <= _block[0]:
                    _block_stack += 1
                    if not _block_stack % self._check_block_stack:
                        _logging_message = f"Node block_sync=Failed, stack_count={_block_stack}, block_height={_block[-1]})"
                        self.cfg.logger.error(_logging_message)
                        if _error_counter.push_hit():
                            if self.config.get('CHECK_SEEDS'):
                                p2p_rs, rpc_rs = self.check_up_seeds(self._p2p_port, self._rpc_port)
                                if p2p_rs:
                                    self.cfg.logger.warning(f"Node check_up_seeds(p2p)={p2p_rs}")
                                if rpc_rs:
                                    self.cfg.logger.warning(f"Node check_up_seeds(rpc)={rpc_rs}")

                            _on_error = True
                            self.cfg.send_auto_slack(
                                msg_text=_logging_message,
                                title='Node block',
                                msg_level='error'
                            )
                    _block[0] = _block[-1]
                else:
                    pawn.set(is_avail_node_status=True)
                    if _block_stack >= self._check_block_stack:
                        _logging_message = f"Node block_sync=OK, stack_count={_block_stack}, block_height={_block[-1]})"
                        self.cfg.logger.info(_logging_message)
                        self.cfg.send_auto_slack(
                            msg_text=_logging_message,
                            title='Node block',
                            msg_level='info'
                        )

                    _block_stack = 0
                    _block[0] = _block[-1]
            if _peer_stack >= self._stack_limit or _block_stack >= self._stack_limit:
                _logging_message = f"Node stack_limit over. PEER STACK={_peer_stack}, BLOCK STACK={_block_stack}, Block={_block[-1]}"
                self.cfg.logger.error(_logging_message)
                self.cfg.send_auto_slack(
                    msg_text=_logging_message,
                    title='Node shutdown',
                    msg_level='warning'
                )
                sys.exit(127)

            if _on_error:
                pawn.set(is_avail_node_status=False)

            await asyncio.sleep(self._check_interval)

    def _find_increase_item(self, find_key=[], status=None):
        _result = {}
        if isinstance(status, dict):
            for key, value in status.items():
                if key in find_key and value > 0:
                    _result[key] = value
        return _result

    async def check_validator_status(self):
        _check_interval = self.config.get('CHECK_INTERVAL', 15)
        if self.cfg.get_base_config('USE_VALIDATOR_HEALTH_CHECK'):
            self.cfg.logger.info(f"Starting validator status, interval={_check_interval}")
            _previous_status = {}
            # error_counter = ErrorCounter()
            _first_load = True

            while True:
                _endpoint = None
                if not pconf().is_avail_node_status:
                    pawn.console.log(f"Abnormal status, {pconf().last_endpoint} != {self.validator_checker.public_endpoint}")
                    if pconf().last_endpoint != self.validator_checker.public_endpoint:
                        _endpoint = self.validator_checker.public_endpoint
                        pawn.console.debug(f"[red][{pconf().is_avail_node_status}] Abnormal node. It will be changed endpoint to {_endpoint}")
                        pawn.set(last_endpoint=_endpoint)
                elif pconf().last_endpoint != self.validator_checker.local_endpoint:
                    # pawn.console.log(f"last_endpoint={pconf().last_endpoint}")
                    pawn.set(last_endpoint=None)
                    _endpoint = self.validator_checker.local_endpoint
                    pawn.console.debug(f"[red][{pconf().is_avail_node_status}] Normal node. It will be changed endpoint to {_endpoint}")

                if not self.validator_checker.key_exist:
                    self.validator_checker.find_my_owner_key(timeout=3, url=pconf().last_endpoint)

                _status = self.validator_checker.fetch_status(url=pconf().last_endpoint)
                _status = convert_dict_hex_to_int(_status)

                found_items = self._find_increase_item(['flags', 'nonVotes'], _status)

                if _first_load and found_items:
                    self.cfg.send_auto_slack(
                        title='Abnormal Validator Status',
                        msg_text=found_items,
                        msg_level='warning'
                    )

                exclude_keys = ["height"]

                if isinstance(_previous_status, dict) and isinstance(_status, dict):
                    added, removed, modified, same = dict_compare(_previous_status, _status, exclude_keys=exclude_keys)

                    if added or removed or modified:
                        self.cfg.logger.debug(f"added={added}, removed={removed}, modified={modified}")

                    if modified:
                        message = ""
                        for changed_key, values in modified.items():
                            message += f"Changed '{changed_key}' status: {values[0]}=>{values[1]} \n"

                        self.cfg.logger.info(message)
                        # if error_counter.push_hit():
                        #     pawn.console.log(f"[red] SENT {error_counter.get_data()}")
                        self.cfg.send_auto_slack(
                            title='[WARN] Changed Validator Status',
                            msg_text=f"{message}",
                            msg_level='warning'
                        )

                status = dict_to_line(
                    _status,
                    end_separator=", "
                )
                if status:
                    self.cfg.logger.info(f"Validator status response: {status}")
                _previous_status = _status
                _first_load = False

                await asyncio.sleep(_check_interval)

    def run(self, ):
        self.check_node()


def dict_compare(d1, d2, exclude_keys=[]):
    d1 = deepcopy(d1)
    d2 = deepcopy(d2)
    if exclude_keys:
        for k in exclude_keys:
            if d1.get(k):
                del d1[k]
            if d2.get(k):
                del d2[k]

    d1_keys = set(d1.keys())
    d2_keys = set(d2.keys())
    shared_keys = d1_keys.intersection(d2_keys)
    added = d1_keys - d2_keys
    removed = d2_keys - d1_keys
    modified = {o: (d1[o], d2[o]) for o in shared_keys if d1[o] != d2[o]}
    same = set(o for o in shared_keys if d1[o] == d2[o])
    return added, removed, modified, same


class OSChecker:
    def __init__(self, ):
        pass

    def name(self, ):
        return subprocess.check_output('hostname', shell=True).decode().split('\n')[0]

    def live(self, host, timeout=5):
        result_ping = ping(host, timeout=timeout)
        return result_ping if result_ping else 0.0

    def disk(self, ):
        pass

    def memory(self, ):
        pass

    def port(self, address, port):
        a_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        location = (address, port)
        result_of_check = a_socket.connect_ex(location)
        if result_of_check == 0:
            return_val = True
        else:
            return_val = False
        a_socket.close()
        return return_val


class PeerChecker:
    def __init__(self, ):
        pass

    def peer_status(self, url, timeout=3):
        try:
            res = requests.get(url, timeout=timeout)
        except:
            return {}
        else:
            if res and res.status_code == 200:
                res = res.json()
                if isinstance(res, list):
                    res = res[0]
            return res


class ValidatorChecker:
    def __init__(self, owner_address="", cfg=None, public_endpoint=None, local_endpoint='localhost'):
        self._owner_address = owner_address
        self.cfg = cfg
        self.public_endpoint = public_endpoint
        self.local_endpoint = local_endpoint

        self._endpoint = local_endpoint

        if not self._endpoint:
            self._endpoint = local_endpoint
            self.cfg.logger.info(f"Using local endpoint - {self._endpoint}")

        self._status = {}
        self._is_ok = True
        self.key_exist = False
        self.retry_error_counter = ErrorCounter(increase_index=0.5, max_consecutive_count=100)

        if self.cfg.get_base_config('USE_VALIDATOR_HEALTH_CHECK'):
            self.cfg.logger.info(f"ValidatorChecker() with address={self._owner_address}, endpoint={self._endpoint}")

    def fetch_status(self, url=None, timeout=3):
        if not url:
            url = self._endpoint

        if not self.key_exist:
            self.find_my_owner_key(timeout=3)

        self._status = {}

        if self.retry_error_counter.push_hit():
            self._is_ok = True
            self.fetch_validator_info(url, timeout)
            self.fetch_validator_status(url, timeout)
            self.remove_unnecessary_keys_in_status()
        return self._status

    def find_my_owner_key(self, url=None, timeout=3):
        if not url:
            url = self._endpoint

        _validators_info = get_validators_info(endpoint=url, timeout=timeout)
        self.key_exist = False
        if isinstance(_validators_info, dict):
            if _validators_info.get('error'):
                self.retry_error_counter.push_hit()
                return

            if keys_exists(_validators_info, "result", "validators"):
                for validator in _validators_info['result']['validators']:
                    if validator.get('node') == self._owner_address or validator.get('owner') == self._owner_address:
                        self.key_exist = True
                        self._owner_address = validator.get('owner')
                        key_type_message = ""
                        if validator.get('owner') == validator.get('node'):
                            key_type_message = "same"
                        elif validator.get('owner') != validator.get('node'):
                            key_type_message = "different"
                        self.cfg.logger.info(f"Found my {key_type_message} key, owner={validator.get('owner')}, node={validator.get('node')}")

        if not self.key_exist:
            self.cfg.logger.error(f"Your owner key was not found on the {self.cfg.config.get('SERVICE')} - url={url}, address={self._owner_address}")
            self.retry_error_counter.push_hit()

    def _update_status(self, result):
        if result.get('error'):
            self.cfg.logger.error(f"{result.get('error')}")
            self.retry_error_counter.push_hit()
            self._is_ok = False
        elif result.get('result'):
            self._status.update(result.get('result', {}))
            self.retry_error_counter._reset_counter()
        else:
            self.cfg.logger.error(f"Invalid result. result={result}")
            self.retry_error_counter.push_hit()
            self._is_ok = False

    def fetch_validator_info(self, url, timeout):
        if self._is_ok:
            _validator_info = get_validator_info(endpoint=url, timeout=timeout, address=self._owner_address)
            self._update_status(_validator_info)

    def fetch_validator_status(self, url, timeout):
        if self._is_ok:
            _validator_status = get_validator_status(endpoint=url, timeout=timeout, address=self._owner_address)
            self._update_status(_validator_status)

    def remove_unnecessary_keys_in_status(self, remove_keys=None):
        if not remove_keys:
            remove_keys = ["node", "nodePublicKey", "owner", "url"]
        for key in remove_keys:
            if self._status.get(key, "__NOT_DEFINED__") != "__NOT_DEFINED__":
                del self._status[key]


if __name__ == '__main__':
    NC = NodeChecker(use_file=False)
    NC.run()
