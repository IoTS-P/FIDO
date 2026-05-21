import glob
import os
import shutil
import subprocess

from fuzzware_pipeline.logging_handler import logging_handler

from ..naming_conventions import (determine_fuzzers_dirs_for_main_dir,
                                  main_dirs_for_proj)
from ..run_fuzzer import AFL_CMIN

logger = logging_handler().get_logger("pipeline")


def backup_replaytest_directory(dst_path):
    logger.info("Found existing replaytest-folder, creating backup.")
    old_path = dst_path
    new_path = dst_path + "_old"
    try:
        if os.path.isdir(new_path):
            shutil.rmtree(new_path)
        shutil.move(old_path, new_path)
    except Exception as e:
        logger.error(f"{e}")
        exit(0)

def get_all_input_files(project_dir):
    main_dirs = [str(path) for path in main_dirs_for_proj(project_dir)]
    fuzzer_dirs = get_all_fuzzer_dirs(main_dirs)
    inputs = {}
    for main_dir in main_dirs:
        inputs[main_dir] = {}
        for fuzzer_dir in fuzzer_dirs:
            inputs[main_dir][fuzzer_dir] = get_inputs_from_fuzzer_dir(fuzzer_dir)
    return inputs


def get_all_fuzzer_dirs(main_dirs):
    fuzzer_dirs = []
    for main_dir in main_dirs:
        fuzzer_dirs += determine_fuzzers_dirs_for_main_dir(main_dir)
    return fuzzer_dirs

def get_inputs_from_fuzzer_dir(fuzzer_dir):
    input_files = []
    for file in glob.glob(fuzzer_dir + "/queue/*"):
        input_files.append(file)
    return input_files


def copy_file_to_output_folder(fuzzer_test_output_path, input_file): #pylint: disable=inconsistent-return-statements
    input_filename = os.path.basename(input_file)
    test_file = os.path.join(fuzzer_test_output_path, input_filename)
    if not os.path.exists(os.path.dirname(test_file)):
        os.makedirs(os.path.dirname(test_file))
    try:
        shutil.copy(input_file, test_file)
        return test_file
    except Exception as e:
        logger.error(f"Testfile for input: {e}")
        exit(0)

def duplicate_test_file(test_file):
    for i in range(4):
        shutil.copy(test_file, test_file+f"_{i}")

def run_corpus_minimizer_for_fuzzer(fuzzer_test_output_path, config_file, verbose):
    target_args = ['python3', '-m', 'fuzzware_harness.harness', '-m', '-c', str(config_file)]
    minimizer_args = [AFL_CMIN, '-m', 'none', '-U', '-t', '1000', '-K', '-i']
    minimizer_args.append(str(fuzzer_test_output_path))
    minimizer_args.append('-o')
    minimizer_args.append(str(os.path.join(fuzzer_test_output_path, "traces")))

    full_args = minimizer_args + ['--'] + target_args + ['@@']
    try:
        if verbose:
            subprocess.check_call(full_args, env={**os.environ, **{'AFL_SKIP_CRASHES': '1'}})
        else:
            subprocess.check_call(full_args, env={**os.environ, **{'AFL_SKIP_CRASHES': '1'}}, stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        logger.error(f"Command:\n\n{' '.join(full_args)}\n\n failed with error:\n\n {e}")
        exit(1)
