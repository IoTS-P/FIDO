import subprocess
import os

from .naming_conventions import SESS_FILENAME_FMT_FUZZER_N
from .const import EMULATION_RUN_TIMEOUT
from .logging_handler import logging_handler

logger = logging_handler().get_logger("pipeline")

DIR = os.path.dirname(os.path.realpath(__file__))
AFL_FUZZ = "afl-fuzz"
AFL_CMIN = "afl-cmin"

def afl_base_dir(use_aflpp=True):
    afl_dirname = "AFLplusplus" if use_aflpp else "afl"
    return os.path.join(DIR, "../../emulator", afl_dirname)

def run_corpus_minimizer(target_args, input_dir, output_dir, timeout=EMULATION_RUN_TIMEOUT, silent=False, edge_coverage_only=True, use_aflpp=True):
    """
    This performs minimization of a given input directory.
    This can be used prior to starting a new fuzzing session.
    """
    fuzzer_args = [os.path.join(afl_base_dir(use_aflpp), AFL_CMIN), "-m", "none", "-U", "-t", "{:d}".format(timeout)]
    fuzzer_args += ["-i", input_dir]
    fuzzer_args += ["-o", output_dir]

    if edge_coverage_only:
        fuzzer_args += ["-e"]

    full_args = fuzzer_args + ["--"] + target_args + ["@@"]
    logger.info("Starting corpus minimization")
    logger.info("Command line: {}".format(" ".join(full_args)))
    logger.info("afl arguments: {}".format(fuzzer_args))
    logger.info("harness arguments: {}".format(target_args))

    if silent:
        subprocess.check_call(full_args, env={**os.environ, **{'AFL_SKIP_CRASHES': '1'}}, stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    else:
        subprocess.check_call(full_args, env={**os.environ, **{'AFL_SKIP_CRASHES': '1'}})


def run_fuzzer(target_args, input_dir, output_dir, fuzzer_no=1, fuzzers_total=1, masters_total=1, timeout=EMULATION_RUN_TIMEOUT, silent=False, dict_path=None, skip_deterministic=True, use_aflpp=False):
    # Set unlimited memory, Unicorn mode, timeout
    fuzzer_args = [os.path.join(afl_base_dir(use_aflpp), AFL_FUZZ), "-m", "none", "-U", "-t", "{:d}".format(timeout)]
    fuzzer_args += ["-i", input_dir]

    # For AFLPlusPlus with a single fuzzer, pass the parent dir as output
    if use_aflpp and fuzzers_total == 1:
        output_dir = os.path.split(output_dir)[0]

    fuzzer_args += ["-o", output_dir]

    if dict_path is not None:
        fuzzer_args += ["-x", dict_path]

    if fuzzers_total != 1 or use_aflpp:
        is_master = (fuzzers_total != 1 or not skip_deterministic) and fuzzer_no <= masters_total
        # More than one instance
        if is_master:
            fuzzer_args += ["-M"]
            if masters_total != 1:
                out_subdir = SESS_FILENAME_FMT_FUZZER_N.format(fuzzer_no)+":{fuzzer_no:d}/{fuzzer_total:d}".format(fuzzer_no=fuzzer_no, fuzzer_total=masters_total)
                fuzzer_args.append(out_subdir)
            else:
                out_subdir = SESS_FILENAME_FMT_FUZZER_N.format(fuzzer_no)
                fuzzer_args.append(out_subdir)
        else:
            out_subdir = SESS_FILENAME_FMT_FUZZER_N.format(fuzzer_no)
            fuzzer_args += ["-S", out_subdir]
    elif skip_deterministic:
        fuzzer_args += ["-d"]

    logger.info("Starting afl")
    logger.info("afl arguments: {}".format(fuzzer_args))
    logger.info("harness arguments: {}".format(target_args))

    # fork
    # if fuzzer_no == 1:
    full_args = fuzzer_args + ["--"] + target_args + ["@@"]
    logger.info("Command line: {}".format(" ".join(full_args)))
    if silent:
        proc = subprocess.Popen(full_args, env={**os.environ, **{'AFL_SKIP_CRASHES': '1'}}, stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL) #pylint: disable=consider-using-with
    else:
        proc = subprocess.Popen(full_args, env={**os.environ, **{'AFL_SKIP_CRASHES': '1'}}) #pylint: disable=consider-using-with

    return full_args, proc
