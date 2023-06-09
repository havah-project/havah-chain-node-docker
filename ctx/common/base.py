#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import sys
import json
import string
import random
import requests
import time
import socket
import subprocess

from glob import glob
from termcolor import cprint
from common import converter
from config.configure import Configure as CFG
from ffcount import ffcount
from pawnlib.typing import str2bool, is_valid_ipv4
from pawnlib.utils import NetworkInfo, append_http

HAVAH_NETWORK_INFO = {
    "mainnet": {
        "nid": "0x100",
        "cid": "0xfca3fc",
        "seed": "seed.havah.io:7100"
    },
    "vega": {
        "nid": "0x101",
        "cid": "0x630a4",
        "seed": "seed.vega.havah.io:7100"
    }
}

cfg = CFG()


class cd:
    """Context manager for changing the current working directory"""
    def __init__(self, new_path):
        self.new_path = os.path.expanduser(new_path)

    def __enter__(self):
        self.saved_path = os.getcwd()
        os.chdir(self.new_path)

    def __exit__(self, etype, value, traceback):
        os.chdir(self.saved_path)


def run_execute(text=None, cmd=None, cwd=None, check_output=True, capture_output=True, hook_function=None, debug=False, **kwargs):
    """
    Helps run commands
    :param text: just a title name
    :param cmd: command to be executed
    :param cwd: the function changes the working directory to cwd
    :param check_output:
    :param capture_output:
    :param hook_function:
    :param debug:
    :return:
    """
    if cmd is None:
        cmd = text

    start = time.time()

    result = dict(
        stdout=[],
        stderr=None,
        return_code=0,
        line_no=0
    )

    if text != cmd:
        text = f"text='{text}', cmd='{cmd}' :: "
    else:
        text = f"cmd='{cmd}'"

    # if check_output:
    #     # cprint(f"[START] run_execute(), {text}", "green")
    #     cfg.logger.info(f"[START] run_execute() , {text}")
    try:
        # process = subprocess.run(cmd, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd)
        process = subprocess.Popen(cmd, universal_newlines=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=cwd, shell=True)

        for line in process.stdout:
            line_striped = line.strip()
            if line_striped:
                if callable(hook_function):
                    if hook_function == print:
                        print(f"[{result['line_no']}] {line_striped}")
                    else:
                        hook_function(line=line_striped, line_no=result['line_no'], **kwargs)

                if capture_output:
                    result["stdout"].append(line_striped)
                result['line_no'] += 1

        out, err = process.communicate()

        if process.returncode:
            result["return_code"] = process.returncode
            result["stderr"] = err.strip()

    except Exception as e:
        result['stderr'] = e
        raise OSError(f"Error while running command cmd='{cmd}', error='{e}'")

    end = round(time.time() - start, 3)

    if check_output:
        if result.get("stderr"):
            # cprint(f"[FAIL] {text}, Error = '{result.get('stderr')}'", "red")
            cfg.logger.error(f"[FAIL] {text}, Error = '{result.get('stderr')}'")
        else:
            # cprint(f"[ OK ] {text}, timed={end}", "green")
            cfg.logger.info(f"[ OK ] {text}, timed={end}")
    return result


def hook_print(*args, **kwargs):
    """
    Print to output every 10th line
    :param args:
    :param kwargs:
    :return:
    """
    if "amplify" in kwargs.get("line"):
        print(f"[output hook - matching keyword] {args} {kwargs}")

    if kwargs.get("line_no") % 100 == 0:
        print(f"[output hook - matching line_no] {args} {kwargs}")
    # print(kwargs.get('line'))


def write_logging(**kwargs):
    log_file_name = None

    if kwargs.get('log_filename'):
        log_file_name = kwargs['log_filename']

    log_message = f"[{kwargs.get('line_no')}]{converter.todaydate('ms')}, {kwargs.get('line')}"
    # total_file_count = kwargs.get('total_file_count')
    if kwargs.get("line_no") % 100 == 0:
        file_count_string = ""
        if kwargs.get('total_file_count'):
            number_of_files, number_of_dirs = ffcount("/goloop/data")
            file_count_string = f"[{number_of_files}/{kwargs['total_file_count']}]"
        cfg.logger.info(f"{file_count_string} {log_message}")

    logfile = open(log_file_name, "a+")
    logfile.write(f"{log_message} \n")
    logfile.close()


def disable_ssl_warnings():
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def get_public_ipaddr():
    try:
        return requests.get("http://checkip.amazonaws.com", verify=False).text.strip()
    except:
        return None


def get_public_ip():
    try:
        public_ip = requests.get("http://checkip.amazonaws.com", verify=False).text.strip()
        if is_valid_ipv4(public_ip):
            return public_ip
        else:
            cfg.logger.error(f"An error occurred while fetching Public IP address. Invalid IPv4 address - '{public_ip}'")

    except Exception as e:
        cfg.logger.error(f"An error occurred while fetching Public IP address - {e}")
        return ""


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        ipaddr = s.getsockname()[0]
    except Exception:
        ipaddr = '127.0.0.1'
    finally:
        s.close()

    if is_valid_ipv4(ipaddr):
        return ipaddr
    else:
        cfg.logger.error("An error occurred while fetching Local IP address. Invalid IPv4 address")

    return ""


def is_docker():
    return converter.str2bool(os.environ.get("IS_DOCKER", False))


def get_environments():
    environment_defaults = {
        "BASE_DIR": "/goloop",
        "GOLOOP_KEY_SECRET": "/goloop/config/keysecret",
        "KEY_STORE_FILENAME": "",
        "GOLOOP_KEY_STORE": "",
        "KEY_PASSWORD": '',
        "GOLOOP_RPC_ADDR": ":9000",
        "SERVICE": "MainNet",
        "ONLY_GOLOOP": False,
        "ENDPOINT": "",
        "LOCAL_ENDPOINT": "",
        "PUBLIC_ENDPOINT": "",
        "NODE_ADDRESS": "",
        "PLATFORM": 'havah',
        "SEEDS": "",
    }
    env_dict = {}
    for key, default_value in environment_defaults.items():
        if key == "SERVICE" and default_value:
            default_value = default_value.lower()
        elif key == "ONLY_GOLOOP":
            default_value = str2bool(default_value)
        env_dict[key] = os.getenv(key, default_value)

    expected_havah_network = get_expected_havah_network(env_dict.get('SERVICE'))
    if not check_exist_dict_value(env_dict, "SEEDS") and expected_havah_network:
        env_dict['SEEDS'] = expected_havah_network.get('seed')

    return env_dict


def check_exist_dict_value(data, key):
    if isinstance(data, dict) and key in data and data.get(key):
        _value = data.get(key)
        return True
    return False


def get_public_endpoint(network_name=None, platform="havah"):
    if os.getenv('ENDPOINT'):
        return append_http(os.getenv('ENDPOINT'))

    if os.getenv('PUBLIC_ENDPOINT'):
        return append_http(os.getenv('PUBLIC_ENDPOINT'))

    if not network_name:
        network_name = os.getenv('SERVICE', 'MainNet')

    if network_name:
        if "veganet" == network_name.lower().strip():
            network_name = "Vega"
        elif "denebnet" == network_name.lower().strip():
            network_name = "deneb"
    try:
        network_info = NetworkInfo(network_name=network_name, platform=platform)
        return network_info.network_api
    except Exception as e:
        cfg.logger.error(f"'{network_name}' is invalid network name. Cannot found public endpoint. {e} or You can use 'PUBLIC_ENDPOINT' environment ")
        return ""


def get_expected_havah_network(network_name=None):
    if network_name:
        _network_name = network_name.lower().strip()
        if _network_name == "veganet":
            _network_name = "vega"
        elif _network_name == "denebnet":
            _network_name = "deneb"
        return HAVAH_NETWORK_INFO.get(_network_name, {})
    return {}


def get_expected_nid(network_name=None):
    res = get_expected_havah_network(network_name)
    if res.get('nid'):
        return res.get('nid')
    return ""


def get_expected_service(nid=""):
    for service_name, values in HAVAH_NETWORK_INFO.items():
        if values.get('nid') == nid:
            return service_name
    return ""
