#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import append_parent_path
import time
import asyncio
from config.configure import Configure as CFG
from manager.chain_init import ChainInit
from devtools import debug
from pawnlib.config import pawn


cfg = CFG(use_file=True)
cfg.config['ROLE'] = 3
cfg.config['ENDPOINT'] = "http://20.20.5.116:9000"
CI = ChainInit(wait_sock=False)
CI.get_my_info()
debug(CI.get_my_info(address="hxa1c86a7b4cee1b040bb71e0f109dbea6a3e070c1"))
# debug(CI.get_my_info())
