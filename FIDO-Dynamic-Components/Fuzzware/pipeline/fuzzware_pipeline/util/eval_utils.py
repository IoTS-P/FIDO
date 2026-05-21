import copy
import math
import os
import yaml

from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple

from fuzzware_harness.tracing.serialization import parse_bbl_set
from fuzzware_pipeline.logging_handler import logging_handler

from ..naming_conventions import (PREFIX_BASIC_BLOCK_SET, PREFIX_MMIO_TRACE,
                                  fuzzer_dirs_for_main_dir,
                                  input_paths_for_fuzzer_dir, latest_main_dir,
                                  main_dirs_for_proj, trace_for_input_path,
                                  trace_paths_for_main_dir, runtime_log_path_for_proj)
from .. import naming_conventions as nc

logger = logging_handler().get_logger("pipeline")

def add_job_timing_entry(file, func_name, result_status, enqueue_time, start_time, end_time):
    logger.debug("Adding job timing entry for result_status={}, enqueue_time={}, start_time={}, end_time={}".format(result_status, enqueue_time, start_time, end_time))

    if start_time is None:
        start_time = enqueue_time
    if end_time is None:
        end_time = start_time

    # Adding job timing entry for result_status=finished, enqueue_time=2020-01-27 13:56:26.592663, start_time=2020-01-27 13:57:36.528287, end_time=2020-01-27 13:57:38.829949
    file.write("{},{},{},{},{}\n".format(func_name, result_status, enqueue_time, start_time, end_time))

def add_job_timing_entries(file, entries):
    for func_name, result_status, enqueue_time, start_time, end_time in entries:
        # Adding job timing entry for result_status=finished, enqueue_time=2020-01-27 13:56:26.592663, start_time=2020-01-27 13:57:36.528287, end_time=2020-01-27 13:57:38.829949
        add_job_timing_entry(file, func_name, result_status, enqueue_time, start_time, end_time)

def parse_job_datetime_string(time_string):
    return datetime.strptime(time_string, '%Y-%m-%d %H:%M:%S.%f')

def parse_job_timings(job_timings_path):
    res = []

    with open(job_timings_path, "r") as f:
        for line in f.readlines():
            func_name, result_status, enqueue_time, start_time, end_time = line.strip().split(",")

            if start_time == "None":
                start_time = enqueue_time
            if end_time == "None":
                end_time = start_time

            start_time, end_time, enqueue_time = parse_job_datetime_string(start_time), parse_job_datetime_string(end_time), parse_job_datetime_string(enqueue_time)
            res.append((func_name, result_status, enqueue_time, start_time, end_time))

    return res

def dump_job_timing_summary(out_path, timings_per_func_name):
    with open(out_path, "w") as f:
        f.write("# job_name num_jobs total_time_spent_seconds avg_time_spent_seconds\n")
        for func_name, timings in timings_per_func_name.items():
            num_jobs = len(timings)
            total_time_spent = timings[0]
            for ind in range(1, len(timings)):
                total_time_spent += timings[ind]
            total_time_spent = total_time_spent.total_seconds()
            avg_time_spent = round(total_time_spent / num_jobs, 2)

            f.write(f"{func_name} {num_jobs} {total_time_spent} {avg_time_spent}\n")

def load_job_timing_summary(path):
    """
    Loads a previously dumped job timing summary.

    Returns {job_name: (num_jobs, total_time_spent_seconds)} map
    """
    num_jobs_and_time_spent_per_func_name = {}
    with open(path, "r") as f:
        # Skip header
        f.readline()
        for l in f.readlines():
            job_name, num_jobs, total_time_spent_seconds, avg_time_spent_seconds = l.strip().split(" ")
            num_jobs_and_time_spent_per_func_name[job_name] = (int(num_jobs), float(total_time_spent_seconds))
    return num_jobs_and_time_spent_per_func_name

def add_input_file_time_entry(file, seconds_from_start, input_path):
    file.write(f"{seconds_from_start}\t{input_path}\n")

def add_input_file_time_entries(file, file_time_entries):
    for seconds_from_start, input_path in file_time_entries:
        add_input_file_time_entry(file, seconds_from_start, input_path)

def parse_input_file_timings(timing_entries_path):
    res = []

    with open(timing_entries_path, "r") as f:
        for line in f.readlines():
            seconds_from_start, rel_path = line.strip().split("\t")
            seconds_from_start = int(seconds_from_start)
            res.append((seconds_from_start, rel_path))

    return res

def add_coverage_by_second_entries(file, seconds_and_num_bbs):
    for seconds_from_start, num_covered_bbs, new_bb_set in seconds_and_num_bbs:
        addr_text = " ".join(f'{addr:#x}' for addr in sorted(new_bb_set))
        file.write(f"{seconds_from_start:d}\t{num_covered_bbs:d}\t{addr_text}\n")

def dump_coverage_by_second_entries(out_path, coverage_by_second):
    with open(out_path, "w") as f:
        f.write("# seconds_into_experiment\tnum_bbs_total\tnew_bbs_since_last\n")
        add_coverage_by_second_entries(f, coverage_by_second)

def parse_coverage_by_second_file(coverage_file_path):
    res = []

    with open(coverage_file_path, "r") as f:
        for line in f.readlines():
            line = line.rstrip("\n")
            if line.startswith("#"):
                continue

            seconds_from_start, num_covered_bbs, addr_text = line.split("\t")
            seconds_from_start, num_covered_bbs = int(seconds_from_start), int(num_covered_bbs)
            addr_text = addr_text.rstrip("\t")
            addrs = [int(tok, 16) for tok in addr_text.split(" ") if tok]
            res.append((seconds_from_start, num_covered_bbs, set(addrs)))

    return res

def parse_valid_bb_file(valid_bb_path):
    """
    Parse a file which contains valid basic block addresses.

    The file is expected to contain a hexadecimal address per line.
    """
    with open(valid_bb_path, "r") as f:
        return set(int(l, 16) for l in f.readlines() if l.strip())

def valid_bbs_for_proj(projdir, valid_bb_path=None):
    if valid_bb_path is None:
        valid_bb_path = nc.valid_basic_block_list_path_for_proj(projdir)
        if not os.path.exists(valid_bb_path):
            # Fallback: project's parent dir
            valid_bb_path = os.path.join(projdir, "..", nc.PIPELINE_FILENAME_VALID_BB_LIST)
            if not os.path.exists(valid_bb_path):
                return None
    return parse_valid_bb_file(valid_bb_path)

def parse_milestone_bb_file(milestone_bb_path):
    with open(milestone_bb_path, "r") as f:
        return [int(l, 16) for l in f.readlines() if l.strip()]

def dump_milestone_discovery_timings(out_path, discovery_timings, milestone_bbs):
    with open(out_path, "w") as f:
        for milestone_bb in milestone_bbs:
            discovery_timing = discovery_timings.get(milestone_bb, -1)
            f.write(f"{milestone_bb:#x}\t{discovery_timing:d}\n")

def load_milestone_discovery_timings(milestone_discovery_path):
    with open(milestone_discovery_path, "r") as f:
        return [int(l.split("\t")[1], 16) for l in f.readlines() if l.strip()]

def dump_crash_contexts(out_path, crash_input_paths_per_pc_lr):
    with open(out_path, "w") as f:
        f.write("# <num_unique_crashes> pc lr <crash_path_1> <crash_path_2> ...\n")
        for (pc, lr), crashing_inputs in crash_input_paths_per_pc_lr.items():
            f.write(f"{len(crashing_inputs)} {pc:#010x} {lr:#010x}")
            for crashing_input in crashing_inputs:
                f.write(" " + crashing_input)
            f.write("\n")

def parse_crash_contexts(crash_context_path):
    crash_input_paths_per_pc_lr = {}

    with open(crash_context_path, "r") as f:
        # Skip comment line
        f.readline()
        for l in f.readlines():
            if not l:
                continue
            toks = l.split(" ")
            num_crash_paths, pc, lr = int(toks[0]), int(toks[1], 16), int(toks[2], 16)
            crash_input_paths = toks[3:]
            crash_input_paths_per_pc_lr[(pc, lr)] = crash_input_paths

    return crash_input_paths_per_pc_lr

AFL_FUZZER_STATS_FIELD_IND_paths_total    = 3
AFL_FUZZER_STATS_FIELD_IND_unique_crashes = 7
def parse_afl_plot_data(plotdata_file_path, crashes=False):
    res = []
    with open(plotdata_file_path, "r") as f:
        lines = f.readlines()
        # skip first line
        for i in range(1, len(lines)):
            line = lines[i]
            if not line.strip():
                continue
            entries = line.split(",")
            # Extract unix_time, paths_total | unique_crashes
            # # unix_time, cycles_done, cur_path, paths_total, pending_total, pending_favs, map_size, unique_crashes, unique_hangs, max_depth, execs_per_sec
            res.append((int(entries[0]), int(entries[AFL_FUZZER_STATS_FIELD_IND_unique_crashes if crashes else AFL_FUZZER_STATS_FIELD_IND_paths_total])))

    return res

def parse_afl_fuzzer_stats(fuzzer_stats_file_path):
    """
    Parse a fuzzer_stats afl/afl++ file into a dict mapping
    names to values.
    """
    res = {}
    with open(fuzzer_stats_file_path, "r") as f:
        for l in f.readlines():
            if not l:
                continue
            name, value = l.split(":")
            res[name.rstrip()] = value.rstrip()
    return res

def derive_input_file_times_from_afl_plot_data(project_base_dir, crashes=False):
    """
    Derives input file creation timings from afl plot_data entries

    This is a best-effort timing generation for the cases where the pipeline has not
    itself written these timings for (all) input files (and for file systems/OSes where
    the creation timings are not accessible).

    We base the timings based on the plot_data's "paths_total" / "unique_crashes" fields. As an approximation,
    we assume that input queue entries have been generated evenly between the previous and
    the next plot_data entries.

    Returns list of (seconds_from_start, project_relative_input_path)
    """
    project_start_seconds = find_start_time_from_afl(project_base_dir)
    res = []
    for main_dir in main_dirs_for_proj(project_base_dir):
        for fuzzer_dir in fuzzer_dirs_for_main_dir(main_dir):
            prev_stat_seconds, prev_num_input_files = None, 0
            seconds_and_file_path_counts = parse_afl_plot_data(fuzzer_dir.joinpath("plot_data"), crashes=crashes)
            input_paths = input_paths_for_fuzzer_dir(fuzzer_dir, crashes=crashes)
            fuzzer_start_time = 0
            try:
                fuzzer_start_time = int(parse_afl_fuzzer_stats(fuzzer_dir.joinpath("fuzzer_stats"))["start_time"])
            except Exception:
                pass
            for stat_seconds, stat_num_input_files in seconds_and_file_path_counts:
                if stat_seconds < project_start_seconds:
                    # Assume if we've gone back in time that we're using relative time logs (Like AFL++)
                    stat_seconds = stat_seconds + fuzzer_start_time
                if prev_stat_seconds is None:
                    prev_stat_seconds = stat_seconds
                # Distribute the timings of input paths across the interval since the last entry
                num_inputs_since_prev = stat_num_input_files - prev_num_input_files
                num_seconds_since_prev = stat_seconds - prev_stat_seconds

                if num_inputs_since_prev == 0:
                    continue
                for i in range(num_inputs_since_prev):
                    input_seconds_from_start = prev_stat_seconds + round(((i+1) / num_inputs_since_prev) * num_seconds_since_prev) - project_start_seconds
                    input_path = Path(input_paths[prev_num_input_files+i]).relative_to(project_base_dir)
                    res.append((input_seconds_from_start, input_path))
                prev_stat_seconds, prev_num_input_files = stat_seconds, stat_num_input_files
    return res

def find_start_time_from_afl(project_base_dir):
    """
    Finds the start time of a project from afl directories.

    This time is taken from the fuzzer_stats entry of
    the first config iteration's fuzzer.
    """
    try:
        first_main_dir = main_dirs_for_proj(project_base_dir)[0]
    except:
        #if fuzzware-project dir exists but contains no mainXXX dirs
        return 0
    first_fuzzer_dir = fuzzer_dirs_for_main_dir(first_main_dir)[0]
    fuzzer_stats_path = first_fuzzer_dir.joinpath("fuzzer_stats")

    with open(fuzzer_stats_path, "r") as f:
        start_time = int(f.readline().split(": ")[1])

    return start_time

def find_end_time_from_afl(project_base_dir):
    """
    Finds the end time of a project from afl directories.

    This time is taken from the fuzzer_stats entry of
    the last config iteration's fuzzer.
    """
    try:
        last_main_dir = main_dirs_for_proj(project_base_dir)[-1]
    except:
        #if fuzzware-project exists, but contains no mainXXX dirs
        return 0

    last_fuzzer_dir = fuzzer_dirs_for_main_dir(last_main_dir)[-1]
    fuzzer_stats_path = last_fuzzer_dir.joinpath("fuzzer_stats")

    with open(fuzzer_stats_path, "r") as f:
        # Skip first line (start time)
        f.readline()
        end_time = int(f.readline().split(": ")[1])

    return end_time

def parse_run_time_log(project_base_dir):
    """
    Tries to parse the run time log for a fuzzware project dir.

    Returns tuple (planned_runtime_seconds, epoch_start, epoch_end)
    """
    runtime_log_path = runtime_log_path_for_proj(project_base_dir)
    planned_runtime, epoch_start, epoch_end = None, None, None
    if os.path.exists(runtime_log_path):
        with open(runtime_log_path, "r") as f:
            lines = f.readlines()
        planned_runtime = int(lines[0].split(":")[1])
        epoch_start = int(lines[1].split(":")[1])
        if len(lines) >= 3:
            epoch_end = int(lines[2].split(":")[1])

    return planned_runtime, epoch_start, epoch_end

def find_start_time(project_base_dir):
    # First try the log
    _, epoch_start, _ = parse_run_time_log(project_base_dir)
    if epoch_start is not None:
        return epoch_start

    return find_start_time_from_afl(project_base_dir)

def find_run_time(project_base_dir, use_planned_runtime=False):
    """
    Finds the run time for the given project path.

    This time is taken from the logs directory of the
    fuzzware project (if it exists), or approximated from
    AFL directories otherwise.
    """
    # First try to get it from logs (if they are created)
    planned_runtime, epoch_start, epoch_end = parse_run_time_log(project_base_dir)
    if use_planned_runtime:
        return planned_runtime

    if epoch_end is not None:
        return epoch_end - epoch_start

    # If the log did not yield anything, look at inputs

    start_time = find_start_time_from_afl(project_base_dir)
    end_time = find_end_time_from_afl(project_base_dir)
    return end_time - start_time

def hamming_weight(val):
    res = 0
    while val:
        if val & 1:
            res += 1
        val = val >> 1
    return res

def mmio_models_per_access_context(config):
    """
    Parses and transforms a given mmio model config to a
    (pc, addr)->
        ('<typename>', <min_bits>, <min_bytes>)
    mapping.
    """
    from fuzzware_harness.util import parse_symbols
    symbols, _ = parse_symbols(config)
    results = {}
    if 'mmio_models' in config and config['mmio_models']:
        constant_models = config['mmio_models'].get('constant')
        if constant_models:
            from fuzzware_harness.mmio_models.constant import \
                parse_constant_handlers
            for start, _, pc, _ in zip(*parse_constant_handlers(symbols, constant_models)):
                results[(pc, start)] = ('constant', None, 0)

        passthrough_models = config['mmio_models'].get('passthrough')
        if passthrough_models:
            from fuzzware_harness.mmio_models.passthrough import \
                parse_passthrough_handlers
            for addr, pc, _ in zip(*parse_passthrough_handlers(symbols, passthrough_models)):
                results[(pc, addr)] = ('passthrough', None, 0)

        linear_models = config['mmio_models'].get('linear')
        if linear_models:
            from fuzzware_harness.mmio_models.linear import \
                parse_linear_handlers
            for start, _, pc, _, _ in zip(*parse_linear_handlers(symbols, linear_models)):
                results[(pc, start)] = ('linear', None, 0)

        bitextract_models = config['mmio_models'].get('bitextract')
        if bitextract_models:
            from fuzzware_harness.mmio_models.bitextract import \
                parse_bitextract_handlers
            for start, _, pc, byte_size, _, mask in zip(*parse_bitextract_handlers(symbols, bitextract_models)):
                results[(pc, start)] = ('bitextract', hamming_weight(mask), byte_size)

        set_models = config['mmio_models'].get('set')
        if set_models:
            from fuzzware_harness.mmio_models.set import \
                parse_value_set_handlers
            for start, _, pc, val_set in zip(*parse_value_set_handlers(symbols, set_models)):
                # Always consume 1 byte for byte-oriented implementation
                results[(pc, start)] = ('set', math.ceil(math.log2(len(val_set))), 1)

        unmodeled_models = config['mmio_models'].get('unmodeled')
        if unmodeled_models:
            for entry in unmodeled_models.values():
                pc, addr = entry['pc'], entry['addr']
                results[(pc, addr)] = ('unmodeled', None, None)
    return results

def mmio_elim_entry(bytes_raw_total, bytes_consumed_total, bits_required_total):
    entry = {}
    entry["bytes_raw"] = bytes_raw_total
    entry["bytes_fuzzing_input"] = bytes_consumed_total
    entry["bytes_eliminated"] = bytes_raw_total - bytes_consumed_total
    entry["bytes_eliminated_frac"] = round(entry["bytes_eliminated"] / bytes_raw_total if bytes_raw_total else 0, 4)
    entry["if_bitwise_fuzzing_input"] = bits_required_total
    entry["if_bitwise_eliminated"] = (bytes_raw_total * 8) - bits_required_total
    entry["if_bitwise_eliminated_frac"] = round(entry["if_bitwise_eliminated"] / (bytes_raw_total * 8) if bytes_raw_total else 0, 4)
    return entry

def dump_mmio_overhead_elimination_map(mmio_overhead_elim_out_path, mmio_elim_map):
    """
    We dump the map as a list so that it is more easily readable for a human.
    """
    mmio_overhead_elim_results = [{'overall': mmio_elim_map["overall"]}, {"per_model": mmio_elim_map["per_model"]}, {"per_access_context": mmio_elim_map["per_access_context"]}]
    with open(mmio_overhead_elim_out_path, "w") as f:
        yaml.safe_dump(mmio_overhead_elim_results, f)

def load_mmio_overhead_elimination_map(yaml_path):
    """
    Load a previously dumped mmio overhead elimination map
    """
    with open(yaml_path, "r") as yaml_file:
        res = yaml.safe_load(yaml_file.read())

    res_map = {
        'overall': res[0]['overall'],
        'per_model': res[1]['per_model'],
    }

    if len(res) > 2:
        res_map['per_access_context'] = res[2]['per_access_context']

    return res_map

def calculate_mmio_overhead_elimination_per_model_percentage_totals(elim_map):
    bytes_raw_total = elim_map['overall']['bytes_raw']
    for model_name, entry in elim_map['per_model'].items():
        entry['total_bytes_eliminated_frac'] = round(entry["bytes_eliminated"] / bytes_raw_total, 4)
        entry['total_bytes_fuzzing_input_frac'] = round(entry["bytes_fuzzing_input"] / bytes_raw_total, 4)
        entry['total_if_bitwise_eliminated_frac'] = round(entry["if_bitwise_eliminated"] / (bytes_raw_total * 8), 4)
        entry['total_if_bitwise_fuzzing_input_frac'] = round(entry["if_bitwise_fuzzing_input"] / (bytes_raw_total * 8), 4)

def calculate_mmio_overhead_elimination(projdir, config_map):
    from fuzzware_harness.tracing.serialization import (parse_mem_value_text,
                                                        parse_mmio_trace)
    model_per_access_context = mmio_models_per_access_context(config_map)

    main_dir = latest_main_dir(projdir)
    fuzzer_dir = fuzzer_dirs_for_main_dir(main_dir)[0]

    # num_accesses, bytes_raw, bytes_consumed, bits_required
    stats_per_model_type = {}
    stats_per_context = {}
    bytes_raw_total, bytes_consumed_total, bits_required_total = 0, 0, 0
    for input_path in input_paths_for_fuzzer_dir(fuzzer_dir):
        mmio_trace_path = trace_for_input_path(input_path, PREFIX_MMIO_TRACE)
        for _, pc, _, mode, orig_access_size, _, _, address, val_text in parse_mmio_trace(mmio_trace_path):
            if mode != "r":
                continue

            model_data = model_per_access_context.get((pc, address), None)
            if model_data is None:
                typename, min_bits, req_bytes = "unmodeled", None, None
            else:
                typename, min_bits, req_bytes = model_data
            if req_bytes is None:
                req_bytes = orig_access_size
            if min_bits is None:
                min_bits = req_bytes * 8

            # The trace may indicate multiple accesses
            num_vals = len(parse_mem_value_text(val_text))
            for _ in range(num_vals):
                bytes_raw_total += orig_access_size
                bytes_consumed_total += req_bytes
                bits_required_total += min_bits
                per_context_entry = stats_per_context.setdefault((pc, address), [0, 0, 0])
                per_context_entry[0] += orig_access_size
                per_context_entry[1] += req_bytes
                per_context_entry[2] += min_bits
                per_modeltype_entry = stats_per_model_type.setdefault(typename, [0, 0, 0])
                per_modeltype_entry[0] += orig_access_size
                per_modeltype_entry[1] += req_bytes
                per_modeltype_entry[2] += min_bits

    results = {}
    results["overall"] = mmio_elim_entry(bytes_raw_total, bytes_consumed_total, bits_required_total)

    per_model = {}
    for typename, stat_entry in stats_per_model_type.items():
        entry = mmio_elim_entry(*stat_entry)
        per_model[typename] = entry
    results["per_model"] = per_model

    per_access_context = []
    for (pc, mmio_addr), stat_entry in stats_per_context.items():
        entry = mmio_elim_entry(*stat_entry)
        entry['model_type'] = model_per_access_context.get((pc, mmio_addr), ("unmodeled", None, None))[0]
        per_access_context.append({f"{pc:08x}_{mmio_addr:08x}": entry})
    per_access_context = sorted(per_access_context, key=lambda context: list(context.values())[0]['bytes_fuzzing_input'], reverse=True)
    results["per_access_context"] = per_access_context

    return results

def merge_mmio_overhead_elimination_maps(elim_maps):
    """ Merge different MMIO overhead elimination maps.
    This adds values together and re-calculates percentages.
    """
    if not elim_maps:
        return {}

    result = {}

    # 1. Totals
    total_bytes_raw = sum(m['overall']['bytes_raw'] for m in elim_maps if m)
    total_bytes_fuzzing_input = sum(m['overall']['bytes_fuzzing_input'] for m in elim_maps if m)
    total_bits_fuzzing_input = sum(m['overall']['if_bitwise_fuzzing_input'] for m in elim_maps if m)
    result['overall'] = mmio_elim_entry(total_bytes_raw, total_bytes_fuzzing_input, total_bits_fuzzing_input)

    # 2. Per model type
    result['per_model'] = {}
    for model_name in set(sum((list(m['per_model'].keys()) for m in elim_maps if m), [])):
        total_bytes_raw = sum(m['per_model'][model_name]['bytes_raw'] for m in elim_maps if model_name in m['per_model'])
        total_bytes_fuzzing_input = sum(m['per_model'][model_name]['bytes_fuzzing_input'] for m in elim_maps if model_name in m['per_model'])
        total_bits_fuzzing_input = sum(m['per_model'][model_name]['if_bitwise_fuzzing_input'] for m in elim_maps if model_name in m['per_model'])
        result['per_model'][model_name] = mmio_elim_entry(total_bytes_raw, total_bytes_fuzzing_input, total_bits_fuzzing_input)
    calculate_mmio_overhead_elimination_per_model_percentage_totals(result)

    # 3. Per MMIO access context
    # TODO: We don't really needed this for aggregation, can implement for completeness

    return result

def describe_mmio_overhead_elimination_map(target_name, elim_map):
    res = f"=== MMIO Overhead elimination for {target_name} ===\n"

    if 'overall' not in elim_map:
        res += "<EMPTY>"
        return res

    total_bytes_consumed = elim_map['overall']['bytes_raw']
    for model_name in sorted(elim_map['per_model']):
        elim_entry = elim_map['per_model'][model_name]
        elim_percent_bytes = 100*elim_entry['total_bytes_eliminated_frac']
        elim_percent_bits = 100*elim_entry['total_if_bitwise_eliminated_frac']
        input_percent_bytes = 100*elim_entry['total_bytes_fuzzing_input_frac']
        input_percent_bits = 100*elim_entry['total_if_bitwise_fuzzing_input_frac']
        res += f"Model {model_name} eliminated {elim_percent_bytes:.2f}% (bitwise: {elim_percent_bits:.2f}%)"
        res += f" and consumed {input_percent_bytes:.2f}% (bitwise: {input_percent_bits:.2f}%) of fuzzing input.\n"
    elim_percent_bytes = 100*elim_map['overall']['bytes_eliminated_frac']
    elim_percent_bits = 100*elim_map['overall']['if_bitwise_eliminated_frac']
    res += f"In total, models eliminated {elim_percent_bytes:.2f}% (bitwise: {elim_percent_bits:.2f}%) of input."

    return res

def find_traces_covering_all(projdir, bbs: List[int], exclude_bbs: List[int] = (), find_num=1, skip=0, only_last_maindir=True, search_crashes=False) -> List[str]:
    """Find traces which cover given basic block lists.

    bb_lists: list of lists of basic blocks that need to be covered for every entry
    find_num: number of paths to collect for each entry
    skip: number of initial results to skip

    Return (
        found: {bbs1: [path1, path2], bbs2: [path2, path3]},
        not_found: [bbs3, bbs4]
    )
    """

    if only_last_maindir:
        main_dirs = [latest_main_dir(projdir)]
    else:
        main_dirs = main_dirs_for_proj(projdir)[::-1]

    exclude_bbs = set(exclude_bbs)
    bbs = set(bbs)

    # (skips_left, found_paths)
    skips_left = skip
    trace_paths = []
    for main_dir in main_dirs:
        for trace_path in trace_paths_for_main_dir(main_dir, PREFIX_BASIC_BLOCK_SET, crash_paths=search_crashes):
            trace_bbls = set(parse_bbl_set(trace_path))
            if trace_bbls.isdisjoint(exclude_bbs) and trace_bbls.issuperset(bbs):
                if skips_left > 0:
                    skips_left -= 1
                else:
                    trace_paths.append(str(trace_path))
                    if len(trace_paths) >= find_num:
                        # Found all we need
                        return trace_paths

    # Return however many we got so far
    return trace_paths

def find_traces_covering_bb(projdir, bb, find_num=1, skip=0) -> List[str]:
    """Find traces which cover given basic blocks.

    Return (
        found: {bb1: trace_path1, bb2: trace_path2},
        not_found: [bb3, bb4]
    )
    """
    return find_traces_covering_all(projdir, (bb, ), find_num=find_num, skip=skip)

def collect_covered_basic_blocks(proj_dir_path, only_last_maindir=True, crashes=False) -> List[int]:
    """
    For the given project directory, collect the set of unique basic block addresses
    which are part of basic block set traces.
    """
    found = set()
    if only_last_maindir:
        main_dirs = [latest_main_dir(proj_dir_path)]
    else:
        main_dirs = main_dirs_for_proj(proj_dir_path)

    for main_dir in main_dirs:
        for trace_path in trace_paths_for_main_dir(main_dir, PREFIX_BASIC_BLOCK_SET, crash_paths=crashes):
            found.update(parse_bbl_set(trace_path))

    return found
