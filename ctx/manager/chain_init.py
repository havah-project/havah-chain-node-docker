#!/usr/bin/with-contenv python3
# -*- coding: utf-8 -*-
import os
import sys
import time
import socket_request
from shutil import copy2

from config.configure import Configure as CFG
from common.icon2 import get_preps, get_inspect, get_validator_status, get_validator_info, get_validator_info_by_node_key
from common.output import write_yaml, open_json
from pawnlib.config import pawn


class ChainInit:
    def __init__(self, use_file=True, wait_sock=True):
        self.cfg = CFG(use_file=use_file)
        self.cfg.logger = self.cfg.get_logger('chain.log')
        self.config = self.cfg.config
        self.unix_socket = self.config.get("GOLOOP_NODE_SOCK", "/goloop/data/cli.sock")
        self.ctl = socket_request.ControlChain(
            unix_socket=self.unix_socket,
            debug=self.config.get('CC_DEBUG', False),
            timeout=int(self.config.get('MAIN_TIME_OUT', 30)),
            logger=self.cfg.logger,
            retry=3
        )
        self.wait_sock = wait_sock
        if self.wait_sock:
            self.chain_socket_checker()
        self.base_dir = self.config.get('BASE_DIR')

    def chain_socket_checker(self, ):
        try_cnt = 0
        while self.ctl.health_check().status_code != 200:
            main_retry_count = int(self.config.get('MAIN_RETRY_COUNT', 200))
            sleep_count = int(self.config.get('MAIN_TIME_SLEEP', 1))
            self.cfg.logger.info(f"[CC][{try_cnt}/{main_retry_count}] {self.ctl.health_check()}, try sleep {sleep_count}s")
            if try_cnt >= main_retry_count:
                self.cfg.logger.error(f"[CC] Socket connection failed. {self.unix_socket}")
                sys.exit(127)
            try_cnt += 1
            time.sleep(sleep_count)

    def get_seeds(self, ):
        seeds = list()
        res = get_preps(self.config.get('ENDPOINT'))
        if res.get('error'):
            self.cfg.logger.error(f"get_preps() {res.get('error')}")
        else:
            preps_addr = [prep['nodeAddress'] for prep in res['result']['preps']]
            inspect = get_inspect(
                self.config.get('ENDPOINT'),
                self.config['CID']
            )
            if inspect.get('error'):
                self.cfg.logger.error(f"[CC] get inspect error - {inspect.get('error')}")
            else:
                for p2p_addr, prep_addr in inspect['module']['network']['p2p']['roots'].items():
                    if prep_addr in preps_addr:
                        seeds.append(p2p_addr)
                self.cfg.logger.info(f"PREPs_count={len(res['result']['preps'])}")
                self.config['SEEDS'] = ",".join(seeds)
                self.cfg.logger.info(f"SEEDS={self.config['SEEDS']}")
                file_name = self.config.get('CONFIG_LOCAL_FILE', '/goloop/configure.yml')
                rs = write_yaml(
                    file_name,
                    self.config
                )
                self.cfg.logger.info(f"{rs}")

    def get_my_address(self):
        try:
            keystore_file = open_json(self.config['GOLOOP_KEY_STORE'])
            my_address = keystore_file.get("address")
        except Exception as e:
            self.cfg.logger.error(f"[ERROR] Load keystore - {e}")
            my_address = None

        return my_address

    def get_my_info(self, address=None):
        if not address:
            my_address = self.get_my_address()
        else:
            my_address = address
        role = self.config.get('ROLE')
        res = get_validator_info_by_node_key(endpoint=self.config.get('ENDPOINT'), address=address)
        validator = res.get("result")

        if res.get('error'):
            self.cfg.logger.error(f"get_validator_info() error=\"{res.get('error')}\"")
        else:
            if isinstance(validator, dict):
                self.cfg.logger.info(f"[CC] Validator name: '{validator.get('name')}', "
                                     f"grade: '{validator.get('grade')}', role: {role}, nonVotes: {int(validator.get('nonVotes'), 16)}")
            else:
                self.cfg.logger.error(f"[CC] It's not a registered keystore(wallet). "
                                      f"Your keystore address => {my_address}")
        return {}

    def set_configure(self, wait_state=True):
        payload = {}
        prev_config = self.ctl.view_chain(detail=True).get_json()

        now_config = {
            "role": int(self.config.get('ROLE', 0)),
            "seedAddress": self.config.get('SEEDS', None)
        }
        self.cfg.logger.info(f"[CC] prev_config={prev_config}")
        self.cfg.logger.info(f"[CC] now_config={now_config}")
        for config_key, config_value in now_config.items():
            if config_value is not None and prev_config.get(config_key, 'THIS_IS_ERROR_VALUE') != config_value:
                self.cfg.logger.info(f"[CC] Set configure key=\"{config_key}\", value=\"{prev_config.get(config_key)}\" => \"{config_value}\"")
                payload[config_key] = config_value

        if payload:
            self.ctl.stop()
            if wait_state:
                self.cfg.logger.info(f"[CC] wait_state={wait_state}")
                try:
                    res = self.ctl.chain_config(payload=payload)
                except Exception as e:
                    res = None
                    self.cfg.logger.error(f"[CC] error chain_config - {e}")
            else:
                self.cfg.logger.info(f"[CC] stop()")
                self.ctl.stop()
                self.cfg.logger.info(f"[CC] Create ControlChain()")
                wait_ctl = socket_request.ControlChain(
                    unix_socket=self.unix_socket,
                    debug=self.config.get('CC_DEBUG', False),
                    wait_state=wait_state
                )
                self.cfg.logger.info(f"[CC] chain_config()")
                res = wait_ctl.chain_config(payload=payload)

            if res and res.get_json()['state'] == "OK":
                self.cfg.logger.info(f"[CC] chain_config() => {res.get_json()['state']}")
            else:
                self.cfg.logger.error(f"[CC] got errors={res}")

            changed_res = self.ctl.view_chain(detail=True).get_json()
            for config_key, config_value in payload.items():
                if changed_res.get(config_key) == config_value:
                    self.cfg.logger.info(f"[CC] Successful Change key=\"{config_key}\", value=\"{changed_res[config_key]}\"")
                else:
                    self.cfg.logger.error(f"[CC] Failed Change key=\"{config_key}\", value=\"{config_value}\" => \"{changed_res[config_key]}\"")
        else:
            self.cfg.logger.info(f"[CC] Set configure, No actions")

    def _join_network(self, ):
        network_name = self.config.get('SERVICE')
        self.cfg.logger.info(f"[CC] Try to join the HAVAH network, network_name={network_name}")
        cid = self.ctl.join(
            seedAddress=self.config.get('SEEDS', '').split(','),
            platform=self.config.get('PLATFORM', 'havah'),
            role=self.config.get('ROLE', 0),
            gs_file=self.config.get('GENESIS_STORAGE', '/goloop/config/icon_genesis.zip'),
        )

        self.cfg.logger.info(f"[CC] Joined the network, result={cid}")
        time.sleep(3)

    def starter(self, ):
        if int(self.config.get('ROLE')) == 3:
            self.get_my_info()
        if self.config.get('FASTEST_START') is True:
            self.cfg.logger.info(f"[CC] START {self.ctl.get_state()}, FASTEST_START={self.config['FASTEST_START']}")
            self.set_configure(wait_state=True)
        else:
            if not self.config.get('SEEDS'):
                self.cfg.logger.error(f"[CC] Please check the SEEDS: {self.config.get('SEEDS')}")
                sys.exit(127)
            self.cfg.logger.info(f"[CC] Starter: SEEDS={self.config.get('SEEDS')}")
            res = self.ctl.get_state()
            pawn.console.log(f"res={res}")

            if isinstance(res, dict) and res.get('cid', None) is None:
                self._join_network()
            else:
                self.set_configure(wait_state=True)

        self.cfg.logger.info(f"[CC] START {self.ctl.get_state()}")
        self.ctl.start()

        try:
            # system_config = ["rpcIncludeDebug", "rpcBatchLimit", "rpcDefaultChannel", "eeInstances"]
            system_config = self.ctl.view_system_config().get("config")
            new_system_config = {}
            for system_key, value in system_config.items():
                if os.getenv(system_key) and str(value).lower() != os.getenv(system_key):
                    system_value = os.getenv(system_key)
                    new_system_config[system_key] = system_value
                    self.cfg.logger.info(f"set {system_key} => {system_value}")

            if new_system_config:
                self.cfg.logger.info(f"[CC][before] system_config = {system_config}")
                res = self.ctl.system_config(payload=new_system_config)
                self.cfg.logger.info(f"[CC][after] system_config = {res}")

        except Exception as e:
            self.cfg.logger.error(f"[CC] Set system config :: {e}")

        self.cfg.logger.info(f"[CC] STATE [{self.ctl.get_state().get('state')}]")


if __name__ == '__main__':
    CI = ChainInit()
