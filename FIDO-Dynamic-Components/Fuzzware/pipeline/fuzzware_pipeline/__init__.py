#!/usr/bin/env python3
import argparse
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from datetime import datetime

from . import naming_conventions as nc
from .logging_handler import logging_handler
from .naming_conventions import (PIPELINE_DIRNAME_STATS, VENV_NAME_MODELING,
                                 config_file_for_main_path,
                                 config_for_input_path, default_base_input_dir,
                                 extra_args_for_config_path,
                                 find_modeling_venv, fuzzer_dirs_for_main_dir,
                                 input_paths_for_fuzzer_dir, input_paths_for_main_dir,
                                 job_timings_file_path, latest_main_dir,
                                 main_dirs_for_proj, project_base,
                                 trace_paths_for_input, trace_paths_for_main_dir, valid_basic_block_list_path_for_proj)
from .util.config import load_extra_args, parse_extra_args
from .util.eval_utils import (collect_covered_basic_blocks, valid_bbs_for_proj,
                                find_traces_covering_all)



logger = logging_handler().get_logger("pipeline")

def auto_int(x):
    return int(x, 0)

def check_cpu_availability(num_local_fuzzer_instances):
    num_available_cores = len(os.sched_getaffinity(0))
    if num_local_fuzzer_instances > num_available_cores:
        logger.error(f"Trying to spawn {num_local_fuzzer_instances} local fuzzer instances failed! Just {num_available_cores} Cores available")
        exit(1)

def check_afl_requirements():
    check_failed = False
    if os.getenv("AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES") is None:
        try:
            with open("/proc/sys/kernel/core_pattern", "rb") as f:
                contents = f.read(1)
                if len(contents) == 1 and contents == b'|':
                    logger.error("Failed: core_pattern check")
                    check_failed = True
        except FileNotFoundError:
            pass

    if os.getenv("AFL_SKIP_CPUFREQ") is None:
        try:
            with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", "rb") as f:
                contents = f.read()
                if not contents.startswith(b'perf'):
                    with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_min_freq", "rb") as f:
                        contents = f.read()
                        min_freq = int(contents)
                    with open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", "rb") as f:
                        contents = f.read()
                        max_freq = int(contents)
                    if min_freq != max_freq:
                        logger.error("Failed: min vs max scaling")
                        check_failed = True
        except FileNotFoundError:
            pass

    if check_failed:
        logger.error("\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\nDid you configure your system so that a plain fuzzer will run correctly?\nFor afl, this would be (on the host, as root):\necho core >/proc/sys/kernel/core_pattern\ncd /sys/devices/system/cpu\necho performance | tee cpu*/cpufreq/scaling_governor\n\nTry the fuzzing command line from the output above\nXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n")
        exit(1)

def check_worker_requirements():
    try:
        find_modeling_venv()
    except Exception:
        logger.error("The modeling virtualenv could not be found. Have you installed the modeling component in the '{}' venv?".format(VENV_NAME_MODELING))
        exit(1)

def check_leftover_args(leftover_args):
    if leftover_args:
        logger.error(f"Did not recognize the following arguments: {leftover_args}")
        exit(1)

def resolve_projdir(projdir):
    if projdir is None:
        projdir = project_base(os.curdir)
        if projdir is None:
            projdir = project_base(os.path.join(os.curdir, nc.DEFAULT_PROJECT_NAME))
    else:
        projdir = project_base(projdir)

    if projdir is None or not os.path.exists(projdir):
        logger.error("Project directory does not exist or not in a project directory")
        exit(1)

    logger.info(f"Got projdir: {projdir:}")

    return projdir

def parse_int_ranges_from_comma_separated_string(cmd_arg):
    res = set()
    for s in cmd_arg.split(","):
        if "-" in s:
            start, end = s.split("-")
            for i in range(int(start), int(end)+1):
                res.add(i)
        else:
            res.add(int(s))
    return sorted(res)

MODE_EXTRACT = "extract"
def do_extract(args, leftover_args):
    from fuzzware_pipeline.util.extract import extract, is_extractable

    check_leftover_args(leftover_args)

    binary_path = args.binary
    if args.is_extractable:
        if is_extractable(binary_path):
            print("[*] Recognized a signature in the file header. Ready for extraction")
        else:
            print("[*] Either this is already a flat binary, or the header format is not yet implemented")

    if args.extract:
        extract(binary_path)

MODE_GENCONFIG = "genconfig"
def do_genconfig(args, leftover_args):
    from fuzzware_harness.util import load_config_deep
    from .output_conventions import segfault_addr_from_emu_output
    from .run_target import run_target
    from .util.config import save_config
    from .util.files import files_in_dir
    from .util.genconfig import (add_region_for_crashing_addr,
                                                  extract_elf, gen_configs,
                                                  is_elf, gen_syms)

    check_leftover_args(leftover_args)

    base_input_dir = args.dyn_base_inputs

    if not os.path.isdir(base_input_dir):
        logger.warning("Base inputs do not exist")
        exit(1)

    if args.fuzz_for != "00:00:00:00":
        logger.warning("Fuzzing not yet implemented for dynamic reconfiguration")
        exit(1)

    binary_path = args.binary
    if not os.path.isfile(binary_path):
        logger.error(f"Binary '{binary_path}' does not exist or is not a regular file")
        exit(1)
    target_dir = os.path.dirname(binary_path)

    # Default to "config.yml" in the target binary's directory
    outpath = args.outpath or (
        os.path.join(target_dir, nc.BASEDIR_FILENAME_CONFIG) if not args.dump_syms
        else os.path.join(target_dir, nc.DEFAULT_FILENAME_SYMS_YML)
    )
    if os.path.exists(outpath):
        logger.error(f"Result path '{outpath}' already exists")
        exit(1)

    #calc bin path if original file was elf
    if is_elf(binary_path):
        logger.info("Got elf file")
        elf_path = binary_path

        if binary_path.endswith(".elf"):
            # "myfirmware.elf" -> "myfirmware.bin"
            binary_path = binary_path[:-len(".elf")] + ".bin"
        else:
            # "myfirmware" -> "myfirmware.bin"
            binary_path = binary_path + ".bin"
        if not os.path.exists(binary_path):
            logger.info("Extracting flat binary")
            extract_elf(elf_path, binary_path)
        else:
            logger.info(f"Binary {binary_path} already extracted")
    else:
        elf_path = None

    if args.dump_syms:
        if not elf_path:
            logger.error("No elf file to dump symbols for was specified")
            exit(1)
        syms = gen_syms(elf_path)
        logger.info(f"Dumping symbols to {outpath}")
        save_config({"symbols": syms}, outpath)
        exit(0)

    baseconfig_path = args.base_config
    if baseconfig_path:
        if not os.path.exists(baseconfig_path):
            logger.error("Base config path does not exist")
            exit(1)
        config_map = load_config_deep(baseconfig_path)
        if 'include' in config_map:
            del config_map['include']
    else:
        config_map = {}

    logger.info(f"Generating config for binary {binary_path}")
    gen_configs(target_dir, config_map, binary_path, elf_path)

    save_config(config_map, outpath)

    logger.info("Running inputs to detect early crashes...")
    keep_going = True
    crash_addresses = set()
    while keep_going:
        keep_going = False
        for input_path in files_in_dir(base_input_dir) + [binary_path]:
            emu_output = str(run_target(outpath, input_path, ["-v"], get_output=True, silent=True))
            crash_addr = segfault_addr_from_emu_output(emu_output)
            if crash_addr not in crash_addresses and crash_addr is not None:
                logger.info(f"Got crashing address. Input: {input_path}. Crash address: 0x{crash_addr:08x}")
                crash_addresses.add(crash_addr)
                # Adjust config and re-run inputs again
                add_region_for_crashing_addr(config_map, crash_addr)
                save_config(config_map, outpath)

                if len(crash_addresses) < args.max_dyn_regions:
                    keep_going = True
                break
    if len(crash_addresses) > 0:
        logger.info(f"Added {len(crash_addresses)} memory region(s) because of early crashes at addresses:")
        logger.info(list(map(hex, crash_addresses)))

MODE_PIPELINE = 'pipeline'
def do_pipeline(args, leftover_args):
    import signal

    from fuzzware_pipeline.pipeline import Pipeline

    check_leftover_args(leftover_args)

    if not os.path.exists(args.target_dir):
        logger.error("Target directory '{}' does not exist".format(args.target_dir))
        exit(1)

    logger.info(f"Executing pipeline at {datetime.now()}")
    logger.info(f"Got projdir: {args.target_dir}")


    if args.base_inputs is None:
        args.base_inputs = os.path.join(args.target_dir, "base_inputs")
    if os.path.isdir(args.base_inputs):
        logger.info("Found 'base_inputs' dir in target directory, using that as base input")
    else:
        logger.info("Could not find 'base_inputs' directory in target base dir, defaulting to generic initial inputs")
        args.base_inputs = default_base_input_dir()
        if not os.path.isdir(args.base_inputs):
            logger.error("Could not find any base inputs directory.")
            exit(1)

    logger.info("Performing initial tests")
    check_cpu_availability(args.num_local_fuzzer_instances)

    if args.skip_afl_cpufreq:
        os.environ['AFL_SKIP_CPUFREQ'] = "1"
    # Fuzzware does not crash the emulator process, disable warning
    os.environ['AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES'] = "1"

    check_afl_requirements()
    check_worker_requirements()
    logger.info("Initial tests successful")

    timeout_seconds = sum(x * int(t) for x, t in zip([1, 60, 3600, 24*3600], reversed(args.run_for.split(":"))))

    status = 0
    pipeline = Pipeline(args.target_dir, args.project_name, args.base_inputs, args.num_local_fuzzer_instances, args.disable_modeling, write_worker_logs=not args.silent_workers, do_full_tracing=args.full_traces, config_name=args.runtime_config_name, timeout_seconds=timeout_seconds, use_aflpp=args.aflpp)

    try:
        if timeout_seconds != 0:
            def handler(signal_no, stack_frame):
                pipeline.request_shutdown()

            # spin up an alarm for the time
            signal.signal(signal.SIGALRM, handler)
            signal.alarm(timeout_seconds)

        pipeline.start()
    except Exception as e:
        logger.error(f"Got exception, shutting down pipeline: {e}")
        import traceback
        traceback.print_exc()
        status = 1
    except:
        logger.debug(f"sys.exc_info: {sys.exc_info()[0]}")
        status = 1
    finally:
        logger.info("Shutting down pipeline now")
        # Deal with ctrl+c spamming without leaving a mess
        for _ in range(10):
            try:
                pipeline.shutdown()
                break
            except KeyboardInterrupt:
                pass
    exit(status)

MODE_EMU = 'emu'
def do_emu(args, leftover_args):
    # For single emulation runs, forward to harness argument parsing
    from fuzzware_harness import harness
    sys.argv[0] = "fuzzware_harness"
    sys.argv.remove(MODE_EMU)
    harness.main()

MODE_FUZZ = 'fuzz'
def do_fuzz(args, leftover_args):
    from fuzzware_pipeline.run_fuzzer import run_fuzzer
    from fuzzware_pipeline.run_target import gen_run_arglist

    base_dir = os.path.dirname(args.config)
    out_dir = os.path.join(base_dir, args.out_subdir)

    if os.path.exists(out_dir) and not os.path.isdir(out_dir):
        logger.error("please specify an output directory, not a file")
        exit(1)

    target_args = gen_run_arglist(args.config, leftover_args + (args.extra_harness_args or []))
    procs = []
    try:
        if args.num_instances == 1:
            _, proc = run_fuzzer(target_args, args.input_dir, out_dir, dict_path=args.dict, use_aflpp=args.aflpp)
            procs.append(proc)
        else:
            for fuzzer_no in range(1, args.num_instances + 1):
                silent = fuzzer_no != 1
                if args.all_masters:
                    _, proc = run_fuzzer(target_args, args.input_dir, out_dir, dict_path=args.dict, fuzzer_no=fuzzer_no, fuzzers_total=args.num_instances, masters_total=args.num_instances, silent=silent, use_aflpp=args.aflpp)
                else:
                    _, proc = run_fuzzer(target_args, args.input_dir, out_dir, dict_path=args.dict, fuzzer_no=fuzzer_no, fuzzers_total=args.num_instances, silent=silent, use_aflpp=args.aflpp)
                procs.append(proc)

        while procs[0].poll() is None:
            time.sleep(10)
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("\nKilling fuzzers")
        for proc in procs:
            proc.kill()


MODE_MODEL = 'model'
def do_model(args, leftover_args):
    try:
        venv_path = find_modeling_venv()
    except Exception:
        logger.error("Cannot find modeling virtualenv. Did you install and set WORKON_HOME?")
        exit(1)

    modeling_script_path = os.path.join(venv_path, "bin", "fuzzware_model")

    sys.argv.remove(MODE_MODEL)
    subprocess.call([modeling_script_path] + sys.argv[1:])

def existing_path(path):
    if not os.path.exists(path):
        raise argparse.ArgumentTypeError("Path '{}' does not exist".format(path))
    return path

def resolve_all(symbols, basic_blocks):
    from fuzzware_harness.util import parse_address_value
    bbs = []

    for bb in basic_blocks:
        try:
            val=int(bb, 16) & (~1)
        except ValueError:
            val=parse_address_value(symbols, bb)
        bbs.append(val)

    return bbs

MODE_REPLAY = 'replay'
def do_replay(args, leftover_args):
    from fuzzware_harness.util import load_config_deep, parse_symbols

    from .naming_conventions import (id_from_path, input_for_trace_path,
                                     input_path_with_id, is_trace_filename,
                                     main_and_fuzzer_number,
                                     queue_or_input_path_for_name)

    config_path = None
    logger.info("Got args.input: {}".format(args.input))

    if args.projdir is not None:
        project_path = args.projdir
    else:
        project_path = resolve_projdir(args.input if os.path.exists(args.input) else None)

    logger.info(f"Executing replay at {datetime.now()}")
    if args.log:
        logger.set_output_file(project_path, 'replay')
        logger.info(f"logging replay output to: {logger.output_file}.log")
    else:
        logger.set_terminal_only()
    if args.covering:
        config = load_config_deep(os.path.join(main_dirs_for_proj(project_path)[0], nc.SESS_FILENAME_CONFIG))
        symbols, _ = parse_symbols(config)
        bbs = resolve_all(symbols, (args.input,))
        # Search for an input which reaches the given basic block
        trace_paths = find_traces_covering_all(project_path, bbs)
        if not trace_paths:
            logger.error("Could not find input covering '{}'".format(args.input))
            exit(1)
        else:
            args.input = trace_paths[0]

    if not os.path.exists(args.input):
        # We are dealing with a queue/crash input name or an input id instead. Look at fuzzer and main ids
        main_id, fuzzer_id = main_and_fuzzer_number(os.curdir)

        if args.main:
            main_id = args.main
        if args.fuzzer:
            fuzzer_id = args.fuzzer

        if not main_id:
            main_path = latest_main_dir(project_path)
            main_id = id_from_path(main_path)
        else:
            main_path = main_dirs_for_proj(project_path)[main_id - 1]

        if fuzzer_id is None:
            if len(fuzzer_dirs_for_main_dir(main_path)) >= 1:
                fuzzer_id = 1
            else:
                logger.error("No fuzzer instance found!")
                exit(1)
            logger.warning("No fuzzer specified, defaulting to fuzzer1.")

        fuzzer_dir = str(fuzzer_dirs_for_main_dir(main_path)[fuzzer_id - 1])

        # Try to parse numeric input id
        try:
            input_id = int(args.input)
        except ValueError:
            input_id = None
            #logger.error("Input neither path nor valid input id")
            #exit(1)

        if input_id is not None:
            # Find input by numeric id
            input_path = input_path_with_id(fuzzer_dir, input_id)
        else:
            # Maybe we got a trace/input file name instead of a full path. Look for a unique path
            input_path = queue_or_input_path_for_name(fuzzer_dir, args.input)
            if input_path is not None and is_trace_filename(args.input):
                input_path = input_for_trace_path(input_path)

        if input_path is None:
            logger.error("Could not find input for '{}' in {}".format(input_id, fuzzer_dir))
            exit(1)
        logger.info("Found input path: {}".format(input_path))
    else:
        # We got a trace or input file
        directory, _ = os.path.split(os.path.realpath(args.input))
        if directory.endswith(nc.SESS_DIRNAME_QUEUE) or directory.endswith(nc.SESS_DIRNAME_CRASHES):
            # input filename, just re-use this file
            input_path = args.input
        elif directory.endswith(nc.SESS_DIRNAME_TEMP_MINIMIZATION) or directory.endswith(nc.SESS_DIRNAME_BASE_INPUTS):
            # input from base directory
            input_path = args.input
            config_path = os.path.join(directory, "..", "config.yml")
        elif os.path.split(directory)[1].startswith(nc.SESS_DIRNAME_TRACES):
            # trace filename, need to translate to input file path
            input_path = input_for_trace_path(args.input)
        else:
            logger.error("Input path needs to be either an input or a trace file")
            exit(1)
    if config_path is None:
        config_path = config_for_input_path(input_path)

    extra_args_file = extra_args_for_config_path(config_path)
    extra_args = parse_extra_args(load_extra_args(extra_args_file), project_path)

    # Run emulator with loaded extra args
    from fuzzware_harness import harness
    sys.argv = ["fuzzware_harness", "-c", config_path, input_path] + leftover_args + extra_args
    logger.info("Commandline: {}".format(" ".join(sys.argv)))
    harness.main()

MODE_REPLAYTEST = 'replaytest'
def do_replaytest(args, leftover_args):
    from .util.consistency import (backup_replaytest_directory,
                                   copy_file_to_output_folder,
                                   duplicate_test_file, get_all_input_files,
                                   run_corpus_minimizer_for_fuzzer)

    check_leftover_args(leftover_args)

    if not os.path.exists(args.project_dir):
        logger.error("Provided project_dir not found!")
        exit(1)

    dst_path = os.path.join(args.project_dir, nc.REPLAY_TEST_DIRECTORY)
    if os.path.isdir(dst_path):
        backup_replaytest_directory(dst_path)

    os.mkdir(dst_path)
    logger.info(f"Executing replaytest at {datetime.now()}")

    if args.log:
        logger.set_output_file(args.project_dir, 'replaytest')
        logger.info(f"logging replaytest output to: {logger.output_file}.log")
    else:
        logger.set_terminal_only()

    logger.info("Collecting all input-files from given directory...")
    inputs_to_test = get_all_input_files(args.project_dir)

    for main_dir in inputs_to_test:
        for fuzzer_dir in inputs_to_test[main_dir]:
            logger.info(f"Running consistency test for {fuzzer_dir}")
            fuzzer_test_files = []
            fuzzer_test_output_path = dst_path + re.split("main00.", fuzzer_dir)[1]
            first_input_in_fuzzer_dir = inputs_to_test[main_dir][fuzzer_dir][0]
            config_file = config_for_input_path(first_input_in_fuzzer_dir)
            for input_file in inputs_to_test[main_dir][fuzzer_dir]:
                test_file = copy_file_to_output_folder(fuzzer_test_output_path, input_file)
                fuzzer_test_files.append(test_file)
                duplicate_test_file(test_file)
            run_corpus_minimizer_for_fuzzer(fuzzer_test_output_path, config_file, args.verbose, args.aflpp)
            if not replay_consistent_for(fuzzer_test_output_path, fuzzer_test_files):
                logger.error(f"Not Consistent for: {fuzzer_test_output_path}")
    #for input_file in inputs_to_test:
    logger.info(f"Replaytest passed for {args.project_dir}!")
    exit(0)

def replay_consistent_for(fuzzer_test_output_path, fuzzer_test_files):
    import glob

    from .naming_conventions import get_sha1_from_file
    traces_output_folder = os.path.join(fuzzer_test_output_path, "traces", ".traces")
    for test_file in fuzzer_test_files:
        reference_file = os.path.join(traces_output_folder, os.path.basename(test_file))
        reference_sha1 = get_sha1_from_file(reference_file)
        filename = os.path.basename(reference_file)
        for file in glob.glob(traces_output_folder + "/*"):
            if os.path.basename(file).startswith(filename):
                file_sha1 = get_sha1_from_file(file)
                if reference_sha1 != file_sha1:
                    logger.warning(f"Found inconstent tuple: {test_file} ({reference_sha1}), {file} ({file_sha1})")
                    return False
    return True


MODE_COV = 'cov'
COV_FORMAT_PLAIN = 'plain'
COV_FORMAT_CARTOGRAPHER = 'cartographer'
def do_cov(args, leftover_args):
    from fuzzware_harness.util import (load_config_deep, parse_symbols,
                                        closest_symbol)
    from .util.cov_formats import (dump_cov_plain, dump_cov_cartographer)

    check_leftover_args(leftover_args)

    projdir = resolve_projdir(args.projdir)

    # If we are searching crashes, make sure such traces exist
    if args.crashes:
        if args.all_main_dirs:
            main_dirs = main_dirs_for_proj(projdir)
        else:
            main_dirs = (latest_main_dir(projdir),)
        if not any([trace_paths_for_main_dir(main_dir, nc.PREFIX_BASIC_BLOCK_SET, crash_paths=True) for main_dir in main_dirs]):
            logger.error("Could not find any crashing traces. These are not generated automatically")
            logger.error("HINT: To generate traces for crashes, see: fuzzware gentraces --crashes bbset")
            exit(1)

    user_defined_basic_blocks = args.basic_blocks
    syms_config = args.syms_config
    valid_bbs = valid_bbs_for_proj(projdir)

    if args.log:
        logger.set_output_file(projdir, 'cov')
        logger.info(f"logging cov output to: {logger.output_file}")
    else:
        logger.set_terminal_only()

    # Read symbols from config
    symbols, addr_to_sym = {}, {}
    if syms_config:
        if not os.path.exists(syms_config):
            logger.error("Symbols config file does not exist")
            exit(1)
    else:
        # No specific config given, just use the config file from one of the main directories
        main_dir_path = main_dirs_for_proj(projdir)[0]
        syms_config = os.path.join(main_dir_path, nc.SESS_FILENAME_CONFIG)

        if not os.path.exists(syms_config):
            syms_config = None

    if syms_config:
        config = load_config_deep(syms_config)
        symbols, addr_to_sym = parse_symbols(config)

    if user_defined_basic_blocks:
        # User-provided symbols / basic blocks
        specific_bbs = list(bb & ~1 for bb in resolve_all(symbols, user_defined_basic_blocks))
        print("Resolved basic block addresses: {}".format(",".join(map(hex, specific_bbs))))

        # User-provided symbols / basic blocks to skip
        if args.exclude:
            excluded_addr_tokens = args.exclude.split(",")
            excluded_bbs = (bb & ~1 for bb in resolve_all(symbols, excluded_addr_tokens))
        else:
            excluded_bbs = ()

        trace_paths = find_traces_covering_all(projdir, specific_bbs, excluded_bbs, args.num_matches, args.skip_num, not args.all_main_dirs, search_crashes=args.crashes)

        if trace_paths:
            print(f"\nFound {len(trace_paths):d} inputs covering all specified addresses:")
            for i, path in enumerate(trace_paths):
                print(f"{i+1:d}. {Path(nc.input_for_trace_path(path)).relative_to(projdir)}")
        else:
            print("Could not find any traces (after skipping) that cover all requested bbs...")
    else:
        # By default, if no specific basic blocks are given, show information about symbols
        symbol_bbs = set(bb & ~1 for bb in symbols.values())

        covered_bbs = collect_covered_basic_blocks(projdir, only_last_maindir=not args.all_main_dirs, crashes=args.crashes)
        if valid_bbs:
            covered_bbs &= valid_bbs

        # Dump out the basic block list in case we are asked to do so
        if args.outfile:
            logger.debug(f"Writing covered basic blocks to {args.outfile}")
            if args.out_format == COV_FORMAT_PLAIN:
                dump_cov_plain(covered_bbs, args.outfile)
            elif args.out_format == COV_FORMAT_CARTOGRAPHER:
                dump_cov_cartographer(covered_bbs, args.outfile)
            else:
                logger.error(f"Unknown coverage outfile format '{args.out_format}'")
                exit(1)

        else:
            if symbol_bbs:
                print("\n====== Found Symbols ======")
                for bb in sorted(symbol_bbs & covered_bbs):
                    print(f"{bb:#010x} ({addr_to_sym.get(bb)})")
    
                print("\n====== Not Found Symbols ======")
                for bb in sorted(symbol_bbs - covered_bbs):
                    print(f"{bb:#010x} ({addr_to_sym.get(bb)})")

            print("\n====== Found Basic Blocks ======")
            for bb in sorted(covered_bbs):
                name, offset = closest_symbol(addr_to_sym, bb)
                if name:
                    offset_str = f" + {offset:#x}" if offset else ""
                    symbol_str = f"{name}{offset_str}"
                else:
                    symbol_str = "UNKN"
                print(f"{bb:#010x} ({symbol_str})")

            if valid_bbs:
                print("\n====== Not Found Basic Blocks ======")
                for bb in sorted(valid_bbs - covered_bbs):
                    name, offset = closest_symbol(addr_to_sym, bb)
                    if name:
                        offset_str = f" + {offset:#x}" if offset else ""
                        symbol_str = f"{name}{offset_str}"
                    else:
                        symbol_str = "UNKN"
                    print(f"{bb:#010x} ({symbol_str})")


RECOGNIZED_TRACE_TYPES = (
    ("mmio", nc.PREFIX_MMIO_TRACE), ("ram", nc.PREFIX_RAM_TRACE),
    ("bb", nc.PREFIX_BASIC_BLOCK_TRACE), ("bbl", nc.PREFIX_BASIC_BLOCK_TRACE),
    ("mmioset", nc.PREFIX_MMIO_SET),
    ("bbset", nc.PREFIX_BASIC_BLOCK_SET), ("bblset", nc.PREFIX_BASIC_BLOCK_SET),
    ("bbhash", nc.PREFIX_BASIC_BLOCK_HASH), ("bblhash", nc.PREFIX_BASIC_BLOCK_HASH)
)

MODE_GENTRACES = 'gentraces'
def do_gentraces(args, leftover_args):
    from .workers.tracegen import gen_missing_maindir_traces

    check_leftover_args(leftover_args)

    projdir = resolve_projdir(args.projdir)

    if args.all:
        args.trace_types = [ "all" ]
        args.fuzzers=args.main_dirs="all"
    if args.trace_types[0] == "all":
        args.trace_types = [ "mmio", "ram", "bb", "bbset", "mmioset", "bbhash" ]
    if args.main_dirs == "all":
        args.main_dirs = ",".join(list(map(str, range(1, len(list(main_dirs_for_proj(projdir)))+1))))
    elif args.main_dirs == "latest":
        args.main_dirs = str(len(list(main_dirs_for_proj(projdir))))
    if args.fuzzers == "all":
        args.fuzzers = ",".join(list(map(str, range(1, len(list(fuzzer_dirs_for_main_dir(nc.latest_main_dir(projdir))))+1))))
    trace_types = args.trace_types

    required_trace_prefixes = []
    for name, prefix in RECOGNIZED_TRACE_TYPES:
        if name in trace_types:
            required_trace_prefixes.append(prefix)

    if len(required_trace_prefixes) != len(trace_types):
        logger.error(f"Did not recognize any or all of the trace types. Recognized trace types: {','.join([v[0] for v in RECOGNIZED_TRACE_TYPES])}")
        exit(1)

    fuzzer_nums = parse_int_ranges_from_comma_separated_string(args.fuzzers)
    main_dir_nums = parse_int_ranges_from_comma_separated_string(args.main_dirs)
    print(f"Got main dir numbers: {main_dir_nums}")
    print(f"Got fuzzers dir numbers: {fuzzer_nums}")
    print(f"Got trace types: {trace_types}")
    print(f"Got trace prefixes: {required_trace_prefixes}")

    # Check whether we will be using native tracing
    # We will collect the data a bit differently as a consequence
    can_use_native_batch = all(prefix in nc.NATIVE_TRACE_FILENAME_PREFIXES for prefix in required_trace_prefixes)

    project_main_dirs = main_dirs_for_proj(projdir)

    print(f"[*] Need to process {len(main_dir_nums)} main director{'y' if len(main_dir_nums)==1 else 'ies'}.")
    if can_use_native_batch:
        print("[+] Using native batch mode as only natively supported traces are to be generated")
    else:
        print(f"[*] We need non-native traces. Doing this one by one. This could take a while...")

    for main_dir_num in main_dir_nums:
        if main_dir_num > len(project_main_dirs):
            break

        main_dir = project_main_dirs[main_dir_num-1]

        print(f"Generating traces for main directory {main_dir}")
        gen_missing_maindir_traces(main_dir, required_trace_prefixes, tracedir_postfix=args.tracedir_postfix, log_progress=True, verbose=args.verbose, crashing_inputs=args.crashes)

MODE_GENSTATS = 'genstats'
STATNAME_COV, STATNAME_MMIO_COSTS, STATNAME_MMIO_OVERHEAD_ELIM = 'coverage', 'modeling-costs', 'mmio-overhead-elim'
STATNAME_CRASH_CONTEXTS, STATNAME_CRASH_TIMINGS = 'crashcontexts', 'crashtimings'
KNOWN_STATNAMES = [
    STATNAME_COV, STATNAME_MMIO_COSTS, STATNAME_MMIO_OVERHEAD_ELIM,
    STATNAME_CRASH_CONTEXTS, STATNAME_CRASH_TIMINGS
]
def do_genstats(args, leftover_args):
    from .util.config import load_config_deep
    from .workers.tracegen import gen_all_missing_traces
    from .util import eval_utils
    from .output_conventions import \
        pc_lr_from_emu_output

    check_leftover_args(leftover_args)

    projdir = resolve_projdir(args.projdir)
    latest_config_path = config_file_for_main_path(main_dirs_for_proj(projdir)[-1])
    config_map = load_config_deep(latest_config_path)

    if args.all:
        args.stats = KNOWN_STATNAMES

    stats_dir = os.path.join(projdir, nc.PIPELINE_DIRNAME_STATS)
    if not os.path.exists(stats_dir):
        logger.warning("Pipeline had not created a statistics directory within the project, creating it now")
        os.mkdir(stats_dir)

    for statname in args.stats:
        if statname not in KNOWN_STATNAMES:
            logger.warning(f"Ignoring unknown stat name: '{statname}' (valid options: {', '.join(KNOWN_STATNAMES)})")


    if STATNAME_COV in args.stats:
        from fuzzware_harness.tracing.serialization import parse_bbl_set

        from .util.eval_utils import (
            add_input_file_time_entries,
            derive_input_file_times_from_afl_plot_data,
            dump_coverage_by_second_entries, dump_milestone_discovery_timings,
            parse_milestone_bb_file)
        from .workers.tracegen import gen_traces

        input_file_timings_path = nc.input_creation_timings_path(projdir)

        file_time_entries = sorted(derive_input_file_times_from_afl_plot_data(projdir), key=lambda e: e[0])
        with open(input_file_timings_path, "w") as f:
            add_input_file_time_entries(f, file_time_entries)

        # Sort by timing
        file_time_entries = sorted(file_time_entries, key=lambda e: e[0])

        # Get valid basic blocks to filter against
        use_valid_listing = not args.i_am_aware_i_am_overcounting_translation_blocks_so_force_skip_valid_bb_file
        if use_valid_listing:
            valid_bbs = valid_bbs_for_proj(projdir, args.valid_bb_file)

            if valid_bbs is None:
                logger.error("genstats coverage: Could not find a valid basic block list file or the specified one does not exist")
                exit(1)

        milestone_bbs, not_yet_found_milestone_bbs = [], set()
        if args.milestone_bb_file is None:
            args.milestone_bb_file = nc.milestone_basic_block_list_path_for_proj(projdir)
            if not os.path.exists(args.milestone_bb_file):
                args.milestone_bb_file = os.path.join(projdir, "..", nc.PIPELINE_FILENAME_CHECKPOINT_BBS)
        elif not os.path.exists(args.milestone_bb_file):
            logger.error("Milestone basic block file does not exist!")
            exit(1)

        if os.path.exists(args.milestone_bb_file):
            milestone_bbs = parse_milestone_bb_file(args.milestone_bb_file)
            not_yet_found_milestone_bbs = set(milestone_bbs)

        logger.info("Generating missing basic block set traces, if any")
        gen_all_missing_traces(projdir, trace_name_prefixes=(nc.PREFIX_BASIC_BLOCK_SET, ), log_progress=True, verbose=args.verbose, force_overwrite=args.force_overwrite)

        milestone_discovery_timings = {}
        seen_bbs = set()
        coverage_by_second = [[0, 0, set()]]
        for seconds_from_start, proj_rel_input_path in file_time_entries:
            input_path = os.path.join(projdir, proj_rel_input_path)
            bb_set_path = nc.trace_for_input_path(input_path, nc.PREFIX_BASIC_BLOCK_SET)

            curr_trace_bbls = set(parse_bbl_set(bb_set_path))
            if use_valid_listing:
                curr_trace_bbls &= valid_bbs

            curr_trace_bbls -= seen_bbs
            seen_bbs |= curr_trace_bbls

            if milestone_bbs:
                # See if we discovered a milestone
                for bb in not_yet_found_milestone_bbs:
                    if bb in curr_trace_bbls:
                        logger.info(f"Found timing for milestone bb {bb:#x} -> {seconds_from_start} seconds")
                        milestone_discovery_timings[bb] = seconds_from_start
                not_yet_found_milestone_bbs -= seen_bbs

            # This trace for same timing as previous one? -> Update existing entry
            if seconds_from_start == coverage_by_second[-1][0]:
                coverage_by_second[-1][1] = len(seen_bbs)
                coverage_by_second[-1][2] |= curr_trace_bbls
            else:
                coverage_by_second.append([seconds_from_start, len(seen_bbs), curr_trace_bbls])

        bb_coverage_out_path = os.path.join(stats_dir, nc.STATS_FILENAME_COVERAGE_OVER_TIME)
        logger.info(f"Writing coverage per second info to {bb_coverage_out_path}")
        dump_coverage_by_second_entries(bb_coverage_out_path, coverage_by_second)

        if milestone_bbs:
            discovery_timings_path = os.path.join(stats_dir, nc.STATS_FILENAME_MILESTONE_DISCOVERY_TIMINGS)
            logger.info(f"Writing milestone discovery info to {discovery_timings_path}")
            dump_milestone_discovery_timings(discovery_timings_path, milestone_discovery_timings, milestone_bbs)

    if STATNAME_CRASH_TIMINGS in args.stats:
        from .util.eval_utils import (
            add_input_file_time_entries,
            derive_input_file_times_from_afl_plot_data
        )

        crash_file_timings_path = nc.crash_creation_timings_path(projdir)
        crash_file_time_entries = sorted(derive_input_file_times_from_afl_plot_data(projdir, crashes=True), key=lambda e: e[0])

        logger.info(f"Writing crash timings to {crash_file_timings_path}")
        with open(crash_file_timings_path, "w") as f:
            add_input_file_time_entries(f, crash_file_time_entries)

    if STATNAME_MMIO_COSTS in args.stats:
        job_timings_path = job_timings_file_path(projdir)

        if not os.path.exists(job_timings_path):
            logger.warning("Job timings file does not exist, skipping summary")
        else:
            job_times_per_type = {}
            for func_name, _, _, start_time, end_time in eval_utils.parse_job_timings(job_timings_path):
                job_times_per_type.setdefault(func_name, [])
                job_times_per_type[func_name].append(end_time - start_time)

            job_timing_summary_out_path = os.path.join(stats_dir, nc.STATS_FILENAME_JOB_TIMING_SUMMARY)
            logger.info(f"Writing job timing summary to {job_timing_summary_out_path}")
            eval_utils.dump_job_timing_summary(job_timing_summary_out_path, job_times_per_type)

    if STATNAME_MMIO_OVERHEAD_ELIM in args.stats:
        logger.info("Generating full MMIO traces. This will take a while...")
        tracegen_args = argparse.Namespace(dryrun=False, trace_types=["mmio"], fuzzers="1", main_dirs="latest", projdir=projdir, all=False, tracedir_postfix=None, verbose=False, crashes=False)
        do_gentraces(tracegen_args, None)

        logger.info("Calculating MMIO overhead elimination. This could take a while...")
        mmio_overhead_elim_results = eval_utils.calculate_mmio_overhead_elimination(projdir, config_map)
        mmio_overhead_elim_out_path = os.path.join(stats_dir, nc.STATS_FILENAME_MMIO_OVERHEAD_ELIM)

        logger.info(f"Writing mmio overhead elimination summary to {mmio_overhead_elim_out_path}")
        eval_utils.dump_mmio_overhead_elimination_map(mmio_overhead_elim_out_path, mmio_overhead_elim_results)

    if STATNAME_CRASH_CONTEXTS in args.stats:
        from pathlib import Path
        from .run_target import run_target
        from .util.eval_utils import dump_crash_contexts
        crash_contexts = {}
        for main_dir in main_dirs_for_proj(projdir):
            logger.info(f"Crash contexts from main dir: {main_dir}")
            config_path = None

            for crashing_input in nc.crash_paths_for_main_dir(main_dir):
                if config_path is None:
                    config_path = config_for_input_path(crashing_input)
                    extra_args_file = extra_args_for_config_path(config_path)
                    extra_args = parse_extra_args(load_extra_args(extra_args_file), projdir)
                    if "-v" not in extra_args:
                        extra_args += ["-v"]
                emu_output = str(run_target(config_path, crashing_input, extra_args, get_output=True, silent=True))
                pc, lr = pc_lr_from_emu_output(emu_output)
                crashing_input = str(Path(crashing_input).relative_to(projdir))

                if pc is None:
                    logger.warning(f"An input does not reproduce a crash: {crashing_input}")
                    crash_contexts.setdefault((-404, -404), []).append(crashing_input)
                    continue

                crash_contexts.setdefault((pc, lr), []).append(crashing_input)
                logger.info(f"Got (pc, lr) = ({pc:#010x}, {lr:#010x}) for the following input path: {crashing_input}")

        crash_context_out_path = os.path.join(projdir, nc.PIPELINE_DIRNAME_STATS, nc.STATS_FILENAME_CRASH_CONTEXTS)
        dump_crash_contexts(crash_context_out_path, crash_contexts)


MODE_CHECK = "checkenv"
def do_checkenv(args, leftover_args):
    check_afl_requirements()
    check_cpu_availability(args.num_local_fuzzer_instances)
    check_worker_requirements()
    print("Success")

def main():
    parser = argparse.ArgumentParser(description="Fuzzware")
    def do_help(args, leftover_args):
        parser.parse_args(['-h'])
    parser.set_defaults(func=do_help)

    subparsers = parser.add_subparsers(title="Fuzzware Components", help='Fuzzware utilities:', description="Fuzzware supports its different functions using a set of utilities.\n\nUse 'fuzzware <util_name> -h' for more details.")

    parser_pipeline = subparsers.add_parser(MODE_PIPELINE, help="Running the full pipeline. Fuzzware's main utility.")
    parser_pipeline.set_defaults(func=do_pipeline)

    parser_emu = subparsers.add_parser(MODE_EMU, help="Running the emulator for a single input with manually specified arguments.", add_help=False)
    parser_emu.set_defaults(func=do_emu)

    parser_replay = subparsers.add_parser(MODE_REPLAY, help=f"Convenience wrapper around 'fuzzware {MODE_EMU}' to re-run an input within a fuzzware-project directory.")
    parser_replay.set_defaults(func=do_replay)

    parser_cov = subparsers.add_parser(MODE_COV, help="Search for inputs with specific coverage or dump coverage information.")
    parser_cov.set_defaults(func=do_cov)

    parser_genconfig = subparsers.add_parser(MODE_GENCONFIG, help="Try to generate a base configuration for a given binary or ELF file. DISCLAIMER: This tool is an attempt at generating valid configurations, which you will need to verify and manually adjust in many cases.")
    parser_genconfig.set_defaults(func=do_genconfig)

    parser_gentraces = subparsers.add_parser(MODE_GENTRACES, help="Generate full traces (in addition to set-based default traces) for given fuzzware project.")
    parser_gentraces.set_defaults(func=do_gentraces)

    parser_genstats = subparsers.add_parser(MODE_GENSTATS, help=f"Post-process a given project to generate statistics. Put the results to the project's {PIPELINE_DIRNAME_STATS} directory.")
    parser_genstats.set_defaults(func=do_genstats)

    parser_fuzz = subparsers.add_parser(MODE_FUZZ, help="Running a bare-bone fuzzer for a given configuration. Mostly a testing feature for development purposes.")
    parser_fuzz.set_defaults(func=do_fuzz)

    parser_modeling = subparsers.add_parser(MODE_MODEL, help="Run the modeling component in separation. Mostly a testing feature for development purposes.", add_help=False)
    parser_modeling.set_defaults(func=do_model)

    parser_replaytest = subparsers.add_parser(MODE_REPLAYTEST, help="Checks consistency of fuzzware replay for a given fuzzware project. Mostly a testing feature for develoment purposes.")
    parser_replaytest.set_defaults(func=do_replaytest)

    parser_extract = subparsers.add_parser(MODE_EXTRACT, help=f"Standalone tool to extract files to raw binaries. Experimental support tool for 'fuzzware {MODE_GENCONFIG}'.")
    parser_extract.set_defaults(func=do_extract)

    parser_check = subparsers.add_parser(MODE_CHECK, help="Check for typical environment setup issues. Return non-zero exit status upon error.")
    parser_check.set_defaults(func=do_checkenv)

    # Pipeline command-line arguments
    parser_pipeline.add_argument('target_dir', nargs="?", type=os.path.abspath, default=os.curdir, help="Directory containing the main config. Defaults to the current working dir.")
    parser_pipeline.add_argument('--runtime-config-name', default=nc.SESS_FILENAME_CONFIG, help=f"Main config yaml file name relative to target_dir. Defaults to '{nc.SESS_FILENAME_CONFIG}'.")
    parser_pipeline.add_argument('-p', '--project-name', default=nc.DEFAULT_PROJECT_NAME, help=f"Name of the fuzzing project directory where all the information (input corpus, traces, modeling, ...) regarding the run is stored. Defaults to '{nc.DEFAULT_PROJECT_NAME}'")
    parser_pipeline.add_argument('-n', '--num-local-fuzzer-instances', default=1, type=int, help="Number of local fuzzer instances to use.")
    parser_pipeline.add_argument('--base-inputs', default=None, help="Directory containing the initial inputs to be used for fuzzing. If unspecified, uses simple default inputs.")
    parser_pipeline.add_argument('--run-for', default="00:00:00:00", help="Amount of time to run the pipeline for. Format: DD:HH:MM:SS")
    parser_pipeline.add_argument('--disable-modeling', default=False, action='store_true', help="Disable the generation of MMIO models.")
    parser_pipeline.add_argument('--silent-workers', default=False, action='store_true', help="Disable writing stdout/stderr logs.")
    parser_pipeline.add_argument('--full-traces', default=False, action='store_true', help="Enable generating full traces instead of only generating the (much smaller) set-based traces.")
    parser_pipeline.add_argument('--skip-afl-cpufreq', default=False, action='store_true', help="Skip AFL's performance governor check by setting AFL_SKIP_CPUFREQ=1.")
    parser_pipeline.add_argument('--aflpp', default=False, action="store_true", help="Use AFLplusplus (instead of afl).")

    # Bare-bone Fuzzer command-line arguments
    parser_fuzz.add_argument('out_subdir', help="The output subdirectory name to use.")
    parser_fuzz.add_argument('-c', '--config', default="config.yml", help="Main config yaml file name relative to target_dir.")
    parser_fuzz.add_argument('-i', '--input-dir', default=os.path.dirname(os.path.realpath(__file__))+"/../data/base_inputs", help="Input directory to be passed to afl.")
    parser_fuzz.add_argument('-n', '--num-instances', default=1, type=int, help="Number of local fuzzer instances to spawn.")
    parser_fuzz.add_argument('--all-masters', default=False, action='store_true', help="Run all fuzzer instances as master instances.")
    parser_fuzz.add_argument('--dict', default=None, help="The dictionary file path to be passed to afl. Uses afl-fuzz's -x option.")
    parser_fuzz.add_argument('extra_harness_args', default=[], nargs="*", help="Additional harness runtime arguments, e.g., an instruction limit.")
    parser_fuzz.add_argument('--aflpp', default=False, action="store_true", help="Use AFLplusplus (instead of afl).")

    # Harness command-line arguments
    # No extra emu args as we are passing on parsing to the harness code

    # Modeling command-line arguments
    # No extra emu args as we are passing on parsing to the modeling code

    # Replay command-line arguments
    parser_replay.add_argument('input', help="Either a file path (trace/input) or an input id. For additional arguments to be passed to the emulator, refer to 'fuzzware emu -h'")
    parser_replay.add_argument('-p', '--projdir', help="Fuzzware project directory to search for inputs in. Defaults to searching the current working directory for a fuzzware project root.", default=None)
    parser_replay.add_argument('--main', help="Used only for input ids. Number of the config iteration directory to use. Defaults to the latest config iteration or the working directory.", default=None, type=int)
    parser_replay.add_argument('--fuzzer', help="Used only for input ids. Number fuzzer instance to use. Automatically derived in case the working directory already is a fuzzer directory.", default=None, type=int)
    parser_replay.add_argument('--covering', help="Find an input which reaches a given basic block address or symbol and replay emulation for it", action="store_true", default=False)
    parser_replay.add_argument('--log', action='store_true', help="Enables logging replay output to log-file (logs/replay.log)")

    # Gentraces command-line arguments
    parser_gentraces.add_argument('trace_types', nargs="*", type = str.lower, help=f"List of trace types to generate. Valid options: {'|'.join([v[0] for v in RECOGNIZED_TRACE_TYPES])}. Defaults to '{RECOGNIZED_TRACE_TYPES[0][0]}'.", default=[RECOGNIZED_TRACE_TYPES[0][0]])
    parser_gentraces.add_argument('-p', '--projdir', help="Fuzzware project directory to generate traces for. Defaults to searching the current working directory for a fuzzware project root.", default=None)
    parser_gentraces.add_argument('--crashes', default=False, action="store_true", help="(Optional) Instead of generating traces for queue inputs, generate traces for crashes.")
    parser_gentraces.add_argument('--all', action="store_true", default=False, help="Shorthand for --trace-types=all --main-dirs=all --fuzzers=all")
    parser_gentraces.add_argument('--main-dirs', type = str.lower, help="Comma-separated list of main directory IDs or directory id ranges to generate traces for. E.g., '1,2,3-4'. Special meanings: 'latest', 'all'. Defaults to 'latest'.", default="latest")
    parser_gentraces.add_argument('--fuzzers', type = str.lower, help="Comma-separated list of fuzzer IDs or fuzzer id ranges to generate traces for. E.g., '1,2,3-4'. Defaults to '1'.", default="1")
    parser_gentraces.add_argument('--tracedir-postfix', help="(optional) generate traces in an alternative trace dir. If this is specified, an alternative trace dir is created within the fuzzer dir named traces_<tracedir-postfix>.", default=None)
    parser_gentraces.add_argument('--dryrun', action="store_true", default=False, help="Only list the missing trace files, do not generate actual traces.")
    parser_gentraces.add_argument('-v', '--verbose', action="store_true", default=False, help="Display stdout output of trace generation.")

    # Genstats command-line arguments
    parser_genstats.add_argument('stats', nargs="*", default=(STATNAME_COV, STATNAME_CRASH_TIMINGS,STATNAME_MMIO_COSTS), help=f"The stats to generate. Options: {','.join(KNOWN_STATNAMES)}. Defaults to '{STATNAME_COV} {STATNAME_CRASH_TIMINGS} {STATNAME_MMIO_COSTS}'.")
    parser_genstats.add_argument('-p', '--projdir', help="Fuzzware project directory to generate stats for. Defaults to searching the current working directory for a fuzzware project root.", default=None)
    parser_genstats.add_argument('--all', action="store_true", default=False, help=f"Generate all statistics types ({STATNAME_COV},{STATNAME_MMIO_COSTS},{STATNAME_MMIO_OVERHEAD_ELIM})")
    parser_genstats.add_argument('--valid-bb-file', default=None, help=f"A list of valid basic block addresses to filter coverage against. If not specified, will look for a file '{nc.PIPELINE_FILENAME_VALID_BB_LIST}'")
    parser_genstats.add_argument('--i-am-aware-i-am-overcounting-translation-blocks-so-force-skip-valid-bb-file', action="store_true", default=False, help="Force coverage collection to skip valid-listing basic blocks (NOTE: this will overcount coverage to translation blocks instead of basic blocks and is bad practice when comparing results with other fuzzers).")
    parser_genstats.add_argument('--milestone-bb-file', default=None, help=f"A list of basic block addresses which represent some type of milestone for which we are interested in discovery timings. If not specified, will look for a file '{nc.PIPELINE_FILENAME_CHECKPOINT_BBS}'")
    parser_genstats.add_argument('-v', '--verbose', default=False, action="store_true", help="Prints output of emulator child if set.")
    parser_genstats.add_argument('-f', '--force-overwrite', default=False, action="store_true", help="Force re-generation of traces, deleting existing ones.")

    # Replaytest command-line arguments
    parser_replaytest.add_argument('project_dir', type=os.path.abspath, help="Directory containing the main config")
    parser_replaytest.add_argument('-v', '--verbose', default=False, action="store_true", help="Prints output of afl if set.")
    parser_replaytest.add_argument('--log', action='store_true', help="Enables logging replaytest output to log-file (logs/replaytest.log)")
    parser_replaytest.add_argument('--aflpp', default=False, action="store_true", help="Use AFLplusplus (instead of afl).")

    # Cov command-line arguments
    parser_cov.add_argument('basic_blocks', help="Basic block addresses (hexadecimal) or symbols which need to be covered within a trace. If not provided, general coverage info is dumped checked", nargs="*")
    parser_cov.add_argument('-p', '--projdir', default=None, help="(Optional) Project directory to search coverage for. If not specified, the current working directory is used.")
    parser_cov.add_argument('-c', '--syms-config', default=None, help="(Optional) Fuzzware config file containing symbols (a 'symbols' attribute). Will be derived from projdir if not specified.")
    parser_cov.add_argument('-o', '--outfile', default=None, help="(Optional) Destination file path to dump a set of matching addresses in line-based hex to.")
    parser_cov.add_argument('--out-format', default=COV_FORMAT_PLAIN, help=f"(Optional) Coverage output file format.", choices=(COV_FORMAT_PLAIN, COV_FORMAT_CARTOGRAPHER))
    parser_cov.add_argument('--crashes', default=False, action="store_true", help="(Optional) Instead of searching inputs, search coverage of crashes.")
    parser_cov.add_argument('-e', '--exclude', type=str, default=None, help="(Optional) Comma-separated list of certain symbols/addresses which should not have been hit in the given input. Useful for finding inputs which exhibit specific coverage. Example: 'my_error_func,0x08001234'")
    parser_cov.add_argument('-s', '--skip-num', type=int, default=0, help="(Optional) Skip the first n matching input files which exhibit the given behavior. Useful to cycle through (and replay) different inputs.")
    parser_cov.add_argument('-n', '--num-matches', type=int, default=1, help="(Optional) Find n input paths with the desired coverage.")
    parser_cov.add_argument('--all-main-dirs', default=False, action="store_true", help="(Optional) Search in trace files for all main dirs. Default: Only search the latest main dir.")
    parser_cov.add_argument('--log', action='store_true', help="Enables logging cov output to logfile (logs/cov.log)")

    # Genconfig command-line arguments
    parser_genconfig.add_argument('binary', help="The binary file for which to generate the configuration. ELF Files and other formats will be unpacked to binary form if such file does not yet exist.")
    parser_genconfig.add_argument('-o', "--outpath", default=None, help="(Optional) Generated config path. By default, a config.yml file is generated in the directory of the target binary.")
    parser_genconfig.add_argument('--base-config', default=None, help="(Optional) A base configuration file to use. Memory regions within this config are treated as definitive. If a memory region is included with a 'file' entry which would match the binary (most commonly, this would be '*.bin')")
    parser_genconfig.add_argument('--dump-syms', default=False, action="store_true", help=f"(Optional) Instead of generating a full configuration, just dump symbols to 'outpath' instead. Defaults to false, with symbol output path of '{nc.DEFAULT_FILENAME_SYMS_YML}'.")
    parser_genconfig.add_argument('--dyn-base-inputs', default=default_base_input_dir(), help="(Optional) Base inputs to use for initial memory region re-configuration.")
    parser_genconfig.add_argument('--max-dyn-regions', default=3, action='store_true', help="(Optional) The maximum number of memory regions do dynamically add based on crashes.")
    parser_genconfig.add_argument('--fuzz-for', default="00:00:00:00", help="(Optional) Not yet implemented. In addition to running some base inputs, also use fuzzing to discover missing mapped memory regions from crashes which occur early during fuzzing. Specify the time to run the fuzzer in DD:HH:MM:SS format.")
    parser_genconfig.add_argument('--ti', default="./launchpad", help="(Optional) When creating configs for Texas Instruments (TI) binaries, it may be necessary to add a certain ROM binary, which can be parsed via this command line argument. Another effect is that the ram size will be upped, as this is often an issue with TI samples")

    # Extract command-line argumetns
    parser_extract.add_argument('binary', help="The binary file to check or extract")
    parser_extract.add_argument('-ie', '--is_extractable', action="store_true", help="Check if the file is in a format recognized by the extraction tool")
    parser_extract.add_argument('-e', '--extract', action="store_true", help="Extract the binary")

    # Check command-line arguments
    # No extra args for check util
    parser_check.add_argument('-n', '--num-local-fuzzer-instances', default=1, type=int, help="Number of local fuzzer instances to be used.")

    args, leftover = parser.parse_known_args()
    logger.debug(f"\n\nStarting fuzzware at {datetime.now()}\n\n")

    try:
        args.func(args, leftover)
    except BrokenPipeError:
        # Python flushes standard streams on exit; redirect remaining output
        # to devnull to avoid another BrokenPipeError at shutdown
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        sys.exit(0) # Python exits with error code 1 on EPIPE

if __name__ == '__main__':
    main()
