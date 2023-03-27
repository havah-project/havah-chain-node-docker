#!/usr/bin/with-contenv python3
# -*- coding: utf-8 -*-
import time
from pawnlib.config import pawn
from config.configure import Configure as CFG

from manager.node_checker import NodeChecker
from manager.chain_init import ChainInit

cfg = CFG(
    use_file=True,
    log_name='ICON2',
    log_level='debug'
)

time.sleep(5)
pawn.console.log("Starting ChainInit()")
CI = ChainInit()
CI.starter()


