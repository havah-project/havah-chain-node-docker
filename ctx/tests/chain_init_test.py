#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import append_parent_path
import time
import asyncio
from config.configure import Configure as CFG
from manager.chain_init import ChainInit
from devtools import debug
from pawnlib.config import pawn
from common import icon2

cfg = CFG(use_file=True)
cfg.config['ROLE'] = 3
# cfg.config['ENDPOINT'] = "http://20.20.5.116:9000"
cfg.config['ENDPOINT'] = "https://ctz.vega.havah.io"
CI = ChainInit(wait_sock=False)

debug(icon2.get_validator_info_by_node_key(
        endpoint=cfg.config['ENDPOINT'],
        address='hxd0eb5b221a9f93c1a59afed0074f1f3f343f51da'
    )
)

debug(CI.get_my_info(address="hxd0eb5b221a9f93c1a59afed0074f1f3f343f51da"))
