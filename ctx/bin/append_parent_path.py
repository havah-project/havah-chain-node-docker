import os
import sys

parent_dir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
sys.path.append(parent_dir)
sys.path.append(parent_dir + "/..")

from config.configure import Configure as CFG
cfg = CFG(use_file=True, use_exception_handler=False)
