#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import re
import os
import time
import asyncio
import subprocess
import ntplib

from datetime import datetime
from config.configure import Configure as CFG


class NTPDaemon:
    def __init__(self, ):
        self.chk = re.compile(r'(0\.\d+)')
        self.date_chk = re.compile(r'(\d{8})')
        self.cfg = CFG(use_file=True)
        self.config = self.cfg.config
        self.cfg.logger = self.cfg.get_logger('health.log')
        self.check_time = self.set_check_time()

    def set_check_time(self, ):
        if isinstance(os.getenv('NTP_REFRESH_TIME'), int) and int(os.getenv('NTP_REFRESH_TIME')) > 0:
            return os.getenv('NTP_REFRESH_TIME')
        else:
            try:
                return int(os.getenv('NTP_REFRESH_TIME').strip())
            except Exception as e:
                self.cfg.logger.info("Set the NTP_REFRESH_TIME setting to the default 180.")
                return 180

    def localtime(self, ):
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    def utctime(self, ):
        return datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]

    async def sync_time(self, ):
        while True:
            best_ntp = self.cfg.get_base_config('NTP_SERVER')
            if best_ntp is None:
                try:
                    best_ntp = self.get_best_ntp_server()
                except Exception as e:
                    self.cfg.logger.error(f"[NTP] got error best_ntp = {e}")
                    best_ntp = None
                if best_ntp:
                    self.cfg.logger.info(f"[NTP] Best responsive NTP server is [ {best_ntp} ]")
                else:
                    self.cfg.logger.error(f"[NTP][ERROR] Cannot found NTP servers. NTP_SERVERS={self.config.get('NTP_SERVERS', None)}")
            if best_ntp:
                self.cfg.logger.info(f"[NTP] Time synchronization Start. ({best_ntp})")
                try:
                    code = os.system(f"ntpdate {best_ntp}")
                    if int(code) == 0:
                        self.cfg.logger.info(f"[NTP] Local Time : {self.localtime()}")
                        self.cfg.logger.info(f"[NTP] UTC Time   : {self.utctime()}")
                        self.cfg.logger.info("[NTP] Time synchronization succeeded!")
                    else:
                        self.cfg.logger.error("[NTP] Failed! Check NTP Server or Your Network or SYS_TIME permission.")
                except Exception as e:
                    self.cfg.logger.error(f"[NTP] Failed! Check NTP daemon. {e}")
            await asyncio.sleep(self.check_time * 60)

    def get_best_ntp_server(self, ):
        ntp_servers = self.cfg.get_base_config('NTP_SERVERS')
        min_res_time = None
        selected_server = None
        if ntp_servers:
            self.cfg.logger.info(f"[NTP] NTP Server list : {ntp_servers.split(',')}")
            for ntp_server in ntp_servers.split(","):
                try:
                    client = ntplib.NTPClient()
                    res = client.request(ntp_server, version=3, timeout=1)
                    res_time = res.tx_time - res.orig_time
                    # self.cfg.logger.info(f"[NTP] {ntp_server} : \t{res_time}")
                    if min_res_time is None or res_time < min_res_time:
                        min_res_time = res_time
                        selected_server = ntp_server
                except:
                    self.cfg.logger.error(f"[NTP] {ntp_server} is unresponsive or has timed out")
                    pass
            return selected_server
        else:
            self.cfg.logger.error(f"[NTP] ntp_servers is none, env={self.config.get('NTP_SERVERS')}, "
                                  f"COMPOSE_ENV={self.config.get('NTP_SERVERS')}")

    def ntp_run(self, cmd):
        rs = subprocess.check_output(cmd, shell=True, encoding='utf-8').split('\n')
        code = subprocess.check_output("echo $?", shell=True, encoding='utf-8').split('\n')
        return rs, code

    def run(self, ):
        self.sync_time()


if __name__ == "__main__":
    time.sleep(5)
    ND = NTPDaemon()
    ND.run()
