#!/usr/bin/with-contenv python3
# -*- coding: utf-8 -*-
import time
import asyncio
import append_parent_path
from config.configure import Configure as CFG

from manager.chain_init import ChainInit
from manager.node_checker import NodeChecker
from manager.ntp import NTPDaemon

from pawnlib.config import pawn
from pawnlib.output import get_script_path


pawn.set(
    PAWN_LOGGER=dict(
        log_level="DEBUG",
        stdout_level="INFO",
        log_path=f"{get_script_path(__file__)}/logs",
        stdout=True,
        use_hook_exception=True,
    ),
)

cfg = CFG(use_file=False)
cfg.get_config(use_file=False)
cfg.config['CHECK_INTERVAL'] = 1

async_command_list = []
nc = NodeChecker()
cfg.logger = pawn.app_logger


async_command_list.append(nc.check_node())
async_command_list.append(nc.check_validator_status())

# nd = NTPDaemon()
# async_command_list.append(nd.sync_time())

async def run_managers(command_list=None):
    if isinstance(command_list, list):
        await asyncio.wait(command_list)

if len(async_command_list) > 0:
    cfg.logger.info(f"async_command_list{async_command_list}")
    asyncio.run(run_managers(async_command_list))
else:
    while True:
        time.sleep(60)
