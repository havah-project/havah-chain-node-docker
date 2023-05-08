#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
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
from common.icon2 import call_chain_score, get_validator_status, get_validator_info
from pawnlib.utils import append_http
from pawnlib.config import pawn
from pawnlib.typing import convert_dict_hex_to_int, dict_to_line, ErrorCounter


class NodeChecker:
    def __init__(self, use_file=True):
        self.cfg = CFG(use_file=use_file)
        self.config = self.cfg.config

        self._base_url = ""
        self._my_wallet_address = ""

        self.initialize()
        self.oc = OSChecker()
        self.pc = PeerChecker()
        self.validator_checker = ValidatorChecker(owner_address=self._my_wallet_address, cfg=self.cfg)

        self.unix_socket = self.config.get("GOLOOP_NODE_SOCK", "/goloop/data/cli.sock")
        self.ctl = socket_request.ControlChain(unix_socket=self.unix_socket)
        self.cfg.logger = self.cfg.get_logger('health.log')

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

    def get_rpc_endpoint(self, node_ip='localhost', path=""):
        _p2p_port = int(self.config.get('GOLOOP_P2P_LISTEN', '8080').split(':')[-1])
        _rpc_port = int(self.config.get('GOLOOP_RPC_ADDR', '9000').split(':')[-1])
        return append_http(f"{node_ip}:{_rpc_port}{path}")

    def initialize(self):
        self._base_url = self.get_rpc_endpoint()
        self.get_my_address()

    async def check_node(self, node_ip='localhost'):
        self.cfg.logger.info(f"Starting check node. interval={self.config.get('CHECK_INTERVAL', 10)}")
        _block = [0, 0]
        _peer_stack = 0
        _block_stack = 0
        _stack_limit = int(self.config.get('CHECK_STACK_LIMIT', 360))

        _p2p_port = int(self.config.get('GOLOOP_P2P_LISTEN', '8080').split(':')[-1])
        _rpc_port = int(self.config.get('GOLOOP_RPC_ADDR', '9000').split(':')[-1])

        _endpoint = '/admin/chain/icon_dex'
        _check_peer_stack = self.config.get('CHECK_PEER_STACK', 6)
        _check_block_stack = self.config.get('CHECK_BLOCK_STACK', 10)
        _check_interval = self.config.get('CHECK_INTERVAL', 10)
        _check_timeout = self.config.get('CHECK_TIMEOUT', 10)
        while True:
            peer_rs = self.pc.peer_status(f"http://{node_ip}:{_rpc_port}{_endpoint}", self.config.get('CHECK_TIMEOUT', _check_timeout))
            if not peer_rs:
                _peer_stack += 1
                if not _peer_stack % self.config.get('CHECK_PEER_STACK', _check_peer_stack):
                    self.cfg.logger.error(
                        f"Node API=Failed,stack_count={_peer_stack},Time={int(_peer_stack) * int(self.config.get('CHECK_PEER_STACK', _check_peer_stack))} sec)")
                    if self.config.get('SLACK_WH_URL'):
                        send_slack(self.config['SLACK_WH_URL'],
                                   self.result_formatter(
                                       f"Node API response=Failed,Stack count={_peer_stack},Time={int(_peer_stack) * int(self.config.get('CHECK_PEER_STACK', _check_peer_stack))} sec)"),
                                   'Node health',
                                   msg_level='error'
                                   )
            else:
                self.cfg.logger.info(f"Node API response: {dict_to_line(self.get_peer_goloop(peer_rs), end_separator=', ')}")
                if _peer_stack >= self.config.get('CHECK_PEER_STACK', _check_peer_stack):
                    self.cfg.logger.info(
                        f"Node API=OK,stack_count={_peer_stack},Time={int(_peer_stack) * int(self.config.get('CHECK_PEER_STACK', _check_peer_stack))} sec)")
                    if self.config.get('SLACK_WH_URL'):
                        send_slack(self.config['SLACK_WH_URL'],
                                   self.result_formatter(
                                       f"Node API response=OK,Stack count={_peer_stack},Time={int(_peer_stack) * int(self.config.get('CHECK_PEER_STACK', _check_peer_stack))} sec)"),
                                   'Node health',
                                   msg_level='info'
                                   )
                _peer_stack = 0
                _block[-1] = peer_rs.get('height', 0)
                if _block[-1] <= _block[0]:
                    _block_stack += 1
                    if not _block_stack % self.config.get('CHECK_BLOCK_STACK', _check_block_stack):
                        self.cfg.logger.error(f"Node block_sync=Failed,stack_count={_block_stack},block_height={_block[-1]})")
                        if self.config.get('SLACK_WH_URL'):
                            if self.config.get('CHECK_SEEDS'):
                                p2p_rs, rpc_rs = self.check_up_seeds(_p2p_port, _rpc_port)
                                if p2p_rs:
                                    self.cfg.logger.warning(f"Node check_up_seeds(p2p)={p2p_rs}")
                                if rpc_rs:
                                    self.cfg.logger.warning(f"Node check_up_seeds(rpc)={rpc_rs}")
                            send_slack(self.config['SLACK_WH_URL'],
                                       self.result_formatter(f"Node block_sync=Failed,stack_count={_block_stack},block_height={_block[-1]})"),
                                       'Node block',
                                       msg_level='error'
                                       )
                    _block[0] = _block[-1]
                else:
                    if _block_stack >= self.config.get('CHECK_BLOCK_STACK', _check_block_stack):
                        self.cfg.logger.info(f"Node block_sync=OK,stack_count={_block_stack},block_height={_block[-1]})")
                        if self.config.get('SLACK_WH_URL'):
                            send_slack(self.config['SLACK_WH_URL'],
                                       self.result_formatter(f"Node block_sync=OK,Stack count={_block_stack},Block={_block[-1]})"),
                                       'Node block',
                                       msg_level='info'
                                       )
                    _block_stack = 0
                    _block[0] = _block[-1]
            if _peer_stack >= _stack_limit or _block_stack >= _stack_limit:
                self.cfg.logger.error(f"Node stack_limit over. PEER STACK={_peer_stack}, BLOCK STACK={_block_stack}, Block={_block[-1]}")
                if self.config.get('SLACK_WH_URL'):
                    send_slack(self.config['SLACK_WH_URL'],
                               self.result_formatter(
                                   f"Node stack_limit over. PEER STACK={_peer_stack}, BLOCK STACK={_block_stack}, Block={_block[-1]})"),
                               'Node shutdown',
                               msg_level='warning'
                               )
                sys.exit(127)
            await asyncio.sleep(_check_interval)

    async def check_validator_status(self):
        _check_interval = self.config.get('CHECK_INTERVAL', 15)
        self.cfg.logger.info(f"Starting validator status, interval={_check_interval}")
        _previous_status = {}
        error_counter = ErrorCounter()

        while True:
            _status = self.validator_checker.fetch_status(url=self._base_url)
            _status = convert_dict_hex_to_int(_status)

            if _previous_status and _status:
                added, removed, modified, same = dict_compare(_previous_status, _status)

                if added or removed or modified:
                    self.cfg.logger.debug(f"added={added}, removed={removed}, modified={modified}")

                if modified:
                    message = ""
                    for changed_key, values in modified.items():
                        message += f"Changed '{changed_key}' status: {values[0]}=>{values[1]} \n"
                    self.cfg.logger.info(message)

                    if error_counter.push_hit():
                        pawn.console.log(f"[red] SENT {error_counter.get_data()}")
                        send_slack(
                            url=self.config['SLACK_WH_URL'],
                            title='[WARN] Changed Validator Status',
                            msg_text=f"{message}, consecutive_error_count={error_counter.consecutive_count}",
                            msg_level='warning'
                        )

            status = dict_to_line(
                _status,
                end_separator=", "
            )
            if status:
                self.cfg.logger.info(f"Validator status response: {status}")
            _previous_status = _status
            await asyncio.sleep(_check_interval)

    def run(self, ):
        self.check_node()


def dict_compare(d1, d2):
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
    def __init__(self, owner_address="", cfg=None):
        self._owner_address = owner_address
        self.cfg = cfg
        self._status = {}
        if self.cfg.get_base_config('USE_VALIDATOR_HEALTH_CHECK'):
            self.cfg.logger.info(f"ValidatorChecker() with address={self._owner_address}")

    def fetch_status(self, url, timeout=3):
        self.fetch_validator_info(url, timeout)
        self.fetch_validator_status(url, timeout)
        self.remove_unnecessary_keys_in_status()
        return self._status

    def fetch_validator_info(self, url, timeout):
        _validator_info = get_validator_info(endpoint=url, timeout=timeout, address=self._owner_address)
        if not _validator_info.get('error') and _validator_info.get('result'):
            self._status.update(_validator_info.get('result', {}))

    def fetch_validator_status(self, url, timeout):
        _validator_status = get_validator_status(endpoint=url, timeout=timeout, address=self._owner_address)
        if not _validator_status.get('error') and _validator_status.get('result'):
            self._status.update(_validator_status.get('result', {}))

    def remove_unnecessary_keys_in_status(self, remove_keys=None):
        if not remove_keys:
            remove_keys = ["node", "nodePublicKey", "owner", "url", "height"]
        for key in remove_keys:
            if self._status.get(key, "__NOT_DEFINED__") != "__NOT_DEFINED__":
                del self._status[key]


if __name__ == '__main__':
    NC = NodeChecker(use_file=False)
    NC.run()
