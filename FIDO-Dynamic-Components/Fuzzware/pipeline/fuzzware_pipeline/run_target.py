import subprocess
import sys
assert sys.executable

from .logging_handler import logging_handler

logger = logging_handler().get_logger("pipeline")

def gen_run_arglist(config_path, extra_args):
    res = [sys.executable, "-m", "fuzzware_harness.harness", "-c", config_path] + extra_args

    return res

def run_target(config_path, input_path, extra_args, get_output=False, silent=False, stdout=None, stderr=None):
    """
    Synchronously runs emulator instance a single time.

    :returns: status code of subprocess
    """
    arg_list = gen_run_arglist(config_path, extra_args) + [input_path]
    if not silent:
        logger.info("Running target with\nconfig path: {}\ninput path: {}\nExtra args: {}\n".format(config_path, input_path, extra_args))
        logger.debug("Full command: {}".format(" ".join(arg_list)))

    if get_output:
        return subprocess.run(arg_list, check=False, stdout=subprocess.PIPE).stdout
    return subprocess.call(arg_list, stdout=stdout, stderr=stderr)
