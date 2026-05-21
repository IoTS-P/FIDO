import os
import re
from pathlib import Path
import glob

VENV_NAME_MODELING = "fuzzware-modeling"
ENV_VAR_VENV_PATH = "VIRTUAL_ENV"
ENV_VAR_WORKON_HOME = "WORKON_HOME"
VENV_DIRNAME = ".virtualenvs"
# Look for venv in own home and 'user's home directory (in docker)
VENV_SEARCH_PATHS = [os.path.expanduser("~/"+VENV_DIRNAME), os.path.join("/home", "user", VENV_DIRNAME)]
RQ_DUMP_FILE = "dump.rdb"

# Redis Queue job names
REDIS_QUEUE_NAME_TRACE_GEN_JOBS = "tracegen" # Any jobs regarding generation of
REDIS_QUEUE_NAME_STATE_GEN_JOBS = "stategen"
REDIS_QUEUE_NAME_MODELING = "modeling"

PREFIX_BASIC_BLOCK_TRACE = "bbl_"
PREFIX_RAM_TRACE = "ram_"
PREFIX_MMIO_TRACE = "mmio_"
PREFIX_BASIC_BLOCK_SET = "bblset_"
PREFIX_BASIC_BLOCK_HASH = "bblhash_"
PREFIX_MMIO_SET = "mmioset_"
SET_TRACE_FILENAME_PREFIXES = (PREFIX_BASIC_BLOCK_SET, PREFIX_MMIO_SET)
NATIVE_TRACE_FILENAME_PREFIXES = (PREFIX_BASIC_BLOCK_SET, PREFIX_MMIO_SET, PREFIX_BASIC_BLOCK_HASH)
TRACE_FILENAME_PREFIXES = (PREFIX_BASIC_BLOCK_TRACE, PREFIX_RAM_TRACE, PREFIX_MMIO_TRACE, PREFIX_BASIC_BLOCK_SET, PREFIX_MMIO_SET, PREFIX_BASIC_BLOCK_HASH)
PREFIX_STATEFILE = "access_state"

# parent dir naming conventions
DEFAULT_PROJECT_NAME = "fuzzware-project"
BASEDIR_FILENAME_CONFIG = "config.yml"
DEFAULT_FILENAME_SYMS_YML = "syms.yml"

# pipeline naming conventions
PIPELINE_FILENAME_MMIO_MODEL_CFG = "mmio_config.yml"
PIPELINE_FILENAME_EXIT_AT_CFG = "exit_at_config.yml"
PIPELINE_FILENAME_MAIN_CFG_SNIPPETS = "main_config_snippets.yml"
PIPELINE_FILENAME_JOB_TIMINGS = "job_timings.txt"
PIPELINE_FILENAME_INPUT_CREATION_TIMINGS = "input_creation_timings.txt"
PIPELINE_FILENAME_CRASH_CREATION_TIMINGS = "crash_creation_timings.txt"
PIPELINE_FILENAME_WARNINGS = "WARNINGS.txt"
PIPELINE_FILENAME_EMPTY_INPUT = ".empty_input"
PIPELINE_FILENAME_VALID_BB_LIST = "valid_basic_blocks.txt"
PIPELINE_FILENAME_CHECKPOINT_BBS = "milestone_bbs.txt"
PIPELINE_FILENAME_RUNTIME_LOG = "runtime.txt"

STATS_FILENAME_COVERAGE_OVER_TIME = "covered_bbs_by_second_into_experiment.csv"
STATS_FILENAME_MILESTONE_DISCOVERY_TIMINGS = "milestone_discovery_timings.csv"
STATS_FILENAME_JOB_TIMING_SUMMARY = "job_timing_summary.csv"
STATS_FILENAME_MMIO_OVERHEAD_ELIM = "mmio_overhead_elimination.yml"
STATS_FILENAME_CRASH_CONTEXTS = "crash_contexts.txt"
STATS_GROUND_TRUTH_FILES = [PIPELINE_FILENAME_VALID_BB_LIST, PIPELINE_FILENAME_CHECKPOINT_BBS]

PIPELINE_DIRNAME_MMIO_STATES = "mmio_states"
PIPELINE_DIRNAME_CONFIG_SNIPPETS = "config_snippets"
PIPELINE_DIRNAME_LOGS = "logs"
PIPELINE_DIRNAME_STATS = "stats"

# replaytest naming convention
REPLAY_TEST_DIRECTORY = "replaytest_data"

# fuzzing session naming conventions
SESS_DIRNAME_TRACES = "traces"
SESS_DIRNAME_CRASH_TRACES = "crash_traces"
SESS_DIRNAME_FUZZERS = "fuzzers"
SESS_DIRNAME_BASE_INPUTS = "base_inputs"
SESS_DIRNAME_TEMP_MINIMIZATION = "base_inputs_non_minimized"
SESS_DIRNAME_QUEUE = "queue"
SESS_DIRNAME_CRASHES = "crashes"
SESS_DIRNAME_NECESSARY_FILES = "data"
SESS_FILENAME_CONFIG = BASEDIR_FILENAME_CONFIG
SESS_FILENAME_STATE = "base.state"
SESS_FILENAME_EXTRA_ARGS = "extra_args.txt"
SESS_FILENAME_PREFIX_INPUT = "prefix_input"
SESS_FILENAME_PREFIX_INPUT_ORIG = "prefix_input.orig"
SESS_FILENAME_TEMP_BBL_SET = "bbl_set_prefix_candidate"
SESS_FILENAME_TEMP_MMIO_TRACE = "mmio_trace_prefix_candidate"
SESS_FILENAME_TEMP_PREFIX_INPUT = ".tmp_prefix_input"
SESS_FILENAME_CUR_INPUT = ".cur_input"

SESS_DIRNAME_FUZZER_INST_PREFIX = "fuzzer"
SESS_FILENAME_FMT_FUZZER_N = SESS_DIRNAME_FUZZER_INST_PREFIX+"{:d}"

SESS_NAME_PREFIX_MAIN = "main"
SESS_NAME_PREFIX_ISR = "isr"

MEM_ACCESS_MODE_READ = "r"
MEM_ACCESS_MODE_WRITE = "w"

CONFIG_ENTRY_CATEGORY_BOOT = 'boot'
CONFIG_ENTRY_NAME_BOOT_REQUIRED = 'required'
CONFIG_ENTRY_NAME_BOOT_BLACKLISTED = 'blacklisted'
CONFIG_ENTRY_NAME_BOOT_AVOID = 'avoid'
CONFIG_ENTRY_NAME_BOOT_TARGET = 'target'

INPUT_FILENAME_PREFIX = "id"
BINARY_FILENAME_EXT = "bin"

def default_base_input_dir():
    return os.path.abspath(os.path.dirname(os.path.realpath(__file__))+"/../data/base_inputs")

# We are currently basing everything on file naming conventions instead of heavy caching to allow
# for resumes and to avoid too heavy dependency on global state within the main thread.
def related_trace_path(orig_trace_path, prefix):
    trace_dir, trace_name = os.path.split(orig_trace_path)
    return os.path.join(trace_dir, prefix+trace_name[trace_name.index("_")+1:])

def trace_dirname(tracedir_postfix="", is_crash=False):
    if is_crash:
        name = SESS_DIRNAME_CRASH_TRACES
    else:
        name = SESS_DIRNAME_TRACES

    if tracedir_postfix:
        name += "_" + tracedir_postfix

    return name

def trace_for_input_path(input_path, prefix, tracedir_postfix=""):
    # from: <>/<project_name>/mainXXX/fuzzers/fuzzerX/queue/id:...
    # to  : <>/<project_name>/mainXXX/fuzzers/fuzzerX/traces[POSTFIX]/<prefix>id:...
    # or
    # from: <>/<project_name>/mainXXX/fuzzers/fuzzerX/crashes/id:...
    # to  : <>/<project_name>/mainXXX/fuzzers/fuzzerX/crash_traces[POSTFIX]/<prefix>id:...
    input_dir, filename = os.path.split(input_path)

    basedir, input_dirname = os.path.split(input_dir)

    is_crashing_input = input_dirname == SESS_DIRNAME_CRASHES
    assert(is_crashing_input or input_dirname == SESS_DIRNAME_QUEUE)

    target_trace_dir = trace_dirname(tracedir_postfix, is_crash=is_crashing_input)

    return os.path.join(basedir, target_trace_dir, prefix + filename)

def config_for_input_path(input_path):
    # from: <>/<project_name>/mainXXX/fuzzers/fuzzerX/queue/id:...
    # to  : <>/<project_name/mainXXX/config.yml
    return os.path.join(Path(os.path.abspath(input_path)).parents[3], BASEDIR_FILENAME_CONFIG)

def extra_args_for_config_path(config_path):
    # from: <>/<project_name/mainXXX/config.yml
    # to  : <>/<project_name/mainXXX/extra_args.txt
    return os.path.join(Path(os.path.abspath(config_path)).parent, SESS_FILENAME_EXTRA_ARGS)

def trace_prefix_for_path(trace_path):
    filename = os.path.basename(trace_path)

    for prefix in TRACE_FILENAME_PREFIXES:
        if filename.startswith(prefix):
            return prefix

    assert False

def input_for_trace_path(trace_path):
    trace_directory, filename = os.path.split(trace_path)
    basedir, trace_dirname = os.path.split(trace_directory)

    # Are we dealing with a crashing or non-crashing trace?
    if trace_dirname.startswith(SESS_DIRNAME_CRASH_TRACES):
        input_dirname = SESS_DIRNAME_CRASHES
    else:
        assert(trace_dirname.startswith(SESS_DIRNAME_TRACES))
        input_dirname = SESS_DIRNAME_QUEUE

    input_dir = os.path.join(basedir, input_dirname)
    prefix = trace_prefix_for_path(trace_path)
    return os.path.join(input_dir, filename[len(prefix):])
    # from  : <>/<project_name/fuzzers/fuzzerX/traces/<prefix>id:...
    # to: <>/<project_name/fuzzers/fuzzerX/queue/id:...

def trace_paths_for_input(input_path):
    return (
        trace_for_input_path(input_path, PREFIX_BASIC_BLOCK_TRACE),
        trace_for_input_path(input_path, PREFIX_RAM_TRACE),
        trace_for_input_path(input_path, PREFIX_MMIO_TRACE),
        trace_for_input_path(input_path, PREFIX_BASIC_BLOCK_SET),
        trace_for_input_path(input_path, PREFIX_MMIO_SET),
        trace_for_input_path(input_path, PREFIX_BASIC_BLOCK_HASH),
    )

def trace_paths_for_trace(trace_path):
    return (
        related_trace_path(trace_path, PREFIX_BASIC_BLOCK_TRACE),
        related_trace_path(trace_path, PREFIX_RAM_TRACE),
        related_trace_path(trace_path, PREFIX_MMIO_TRACE),
        related_trace_path(trace_path, PREFIX_BASIC_BLOCK_SET),
        related_trace_path(trace_path, PREFIX_MMIO_SET)
    )

def set_paths_for_trace(trace_path):
    return (
        related_trace_path(trace_path, PREFIX_BASIC_BLOCK_SET),
        related_trace_path(trace_path, PREFIX_MMIO_SET)
    )

def get_input_filename(file_path):
    return file_path[file_path.index("id:"):]

def empty_input_path(project_path):
    return os.path.join(project_path, PIPELINE_FILENAME_EMPTY_INPUT)

def job_timings_file_path(project_path):
    return os.path.join(project_path, PIPELINE_DIRNAME_STATS, PIPELINE_FILENAME_JOB_TIMINGS)

def input_creation_timings_path(project_path):
    return os.path.join(project_path, PIPELINE_DIRNAME_STATS, PIPELINE_FILENAME_INPUT_CREATION_TIMINGS)

def crash_creation_timings_path(project_path):
    return os.path.join(project_path, PIPELINE_DIRNAME_STATS, PIPELINE_FILENAME_CRASH_CREATION_TIMINGS)

# parent/<pipeline_name>/<session_name>/fuzzers/<fuzzerX>/{queue,crashes,hangs}/<input_filename>
input_path_regex = re.compile(".*/([^/]+)/([^/]+)/{fuzzer_dir}/({fuzzername_prefix}\\d+)/(queue|crashes|hangs)/(id:[^/]+)".format(fuzzer_dir=SESS_DIRNAME_FUZZERS, fuzzername_prefix=SESS_DIRNAME_FUZZER_INST_PREFIX))
def get_input_path_components(input_path):
    pipeline_name, session_name, fuzzer_instance_name, input_type, input_filename = input_path_regex.match(input_path).groups()
    return pipeline_name, session_name, fuzzer_instance_name, input_type, input_filename

# parent/<pipeline_name>/<session_name>/fuzzers/<fuzzerX>/traces/<trace_prefix><input_filename>
trace_path_regex = re.compile(".*/([^/]+)/([^/]+)/{fuzzer_dir}/({fuzzername_prefix}\\d+)/(?:{tracedir_name_list})_?[^/]*/({prefix_valid_list})([^/]+id:[^/]+)".format(fuzzer_dir=SESS_DIRNAME_FUZZERS, fuzzername_prefix=SESS_DIRNAME_FUZZER_INST_PREFIX, tracedir_name_list="|".join((SESS_DIRNAME_TRACES, SESS_DIRNAME_CRASH_TRACES)), prefix_valid_list="|".join(TRACE_FILENAME_PREFIXES)))
def get_trace_path_components(trace_path):
    pipeline_name, session_name, fuzzer_instance_name, trace_prefix, input_filename = input_path_regex.match(trace_path).groups()
    return pipeline_name, session_name, fuzzer_instance_name, trace_prefix, input_filename

# mmio_access_state_pc_0000beef_addr_40020124
mmio_access_context_regex = re.compile("pc_([0-9a-f]{8})_addr_([0-9a-f]{8})")
def access_context_from_mmio_state_file_name(mmio_state_name):
    _, _, access_prefix, _ = get_mmio_state_name_components(mmio_state_name)
    pc_str, mmio_str = mmio_access_context_regex.findall(access_prefix)[0]
    return int(pc_str, 16), int(mmio_str, 16)

# session_name+"_"+fuzzer_instance_name+"_"+access_addr_prefix+"_"+input_filename
mmio_state_name_regex = re.compile("([^_]+)_([^_]+)_(.+)_(id:.+)")
def get_mmio_state_name_components(mmio_state_name):
    session_name, fuzzer_instance_name, access_prefix, input_filename = mmio_state_name_regex.match(mmio_state_name).groups()
    return session_name, fuzzer_instance_name, access_prefix, input_filename

def mmio_state_name_prefix_for_input_path(input_path):
    _, session_name, fuzzer_instance_name, _, _ = get_input_path_components(input_path)
    # example: prefix with <session_name>_<fuzzer_name>_
    return session_name+"_"+fuzzer_instance_name+"_"

def mmio_state_name(mmio_state_name_prefix, access_pc, access_mmio_addr, input_name):
    return "{}mmio_access_state_pc_{:08x}_addr_{:08x}_{}".format(mmio_state_name_prefix, access_pc, access_mmio_addr, input_name)

def input_for_mmio_state_path(mmio_state_path):
    directory, mmio_state_name = os.path.split(mmio_state_path)
    pipeline_dir, mmio_states_dirname = os.path.split(directory)
    session_name, fuzzer_instance_name, _, orig_mmio_state_name = get_mmio_state_name_components(mmio_state_name)

    assert mmio_states_dirname == PIPELINE_DIRNAME_MMIO_STATES

    return os.path.join(pipeline_dir, session_name, SESS_DIRNAME_FUZZERS, fuzzer_instance_name, SESS_DIRNAME_QUEUE, get_input_filename(orig_mmio_state_name))

def main_dirs_for_proj(project_path):
    return sorted(Path(project_path).glob(SESS_NAME_PREFIX_MAIN + "*"))

def input_paths_for_fuzzer_dir(fuzzer_dir_path, crashes=False):
    if crashes:
        input_dirname = SESS_DIRNAME_CRASHES
    else:
        input_dirname = SESS_DIRNAME_QUEUE

    return sorted(Path(fuzzer_dir_path).joinpath(input_dirname).glob("id*"))

def input_paths_for_main_dir(main_dir_path, crashes=False):
    if crashes:
        input_dirname = SESS_DIRNAME_CRASHES
    else:
        input_dirname = SESS_DIRNAME_QUEUE

    return sorted(Path(main_dir_path).joinpath(SESS_DIRNAME_FUZZERS).glob(SESS_DIRNAME_FUZZER_INST_PREFIX + "*/" + input_dirname + "/id*"))

def trace_paths_for_main_dir(main_dir_path, trace_prefix, crash_paths=False):
    if crash_paths:
        trace_dir_name = SESS_DIRNAME_CRASH_TRACES
    else:
        trace_dir_name = SESS_DIRNAME_TRACES

    return sorted(Path(main_dir_path).joinpath(SESS_DIRNAME_FUZZERS).glob(SESS_DIRNAME_FUZZER_INST_PREFIX + "*/" + trace_dir_name + "/" + trace_prefix+"*"))

def crash_paths_for_main_dir(main_dir_path):
    return input_paths_for_main_dir(main_dir_path, crashes=True)

def fuzzer_dirs_for_main_dir(main_dir_path):
    return sorted(Path(main_dir_path).joinpath(SESS_DIRNAME_FUZZERS).glob("*"))

def necessary_data_dir(proj_dir_path):
    return Path(proj_dir_path).joinpath(SESS_DIRNAME_NECESSARY_FILES)

def valid_basic_block_list_path_for_proj(proj_dir_path):
    return os.path.join(proj_dir_path, SESS_DIRNAME_NECESSARY_FILES, PIPELINE_FILENAME_VALID_BB_LIST)

def milestone_basic_block_list_path_for_proj(proj_dir_path):
    return os.path.join(proj_dir_path, SESS_DIRNAME_NECESSARY_FILES, PIPELINE_FILENAME_CHECKPOINT_BBS)

def runtime_log_path_for_proj(proj_dir_path):
    return os.path.join(proj_dir_path, PIPELINE_DIRNAME_LOGS, PIPELINE_FILENAME_RUNTIME_LOG)

def config_file_for_main_path(main_dir_path):
    return Path(main_dir_path).joinpath(SESS_FILENAME_CONFIG)

def input_path_with_id(queue_dir, id_no):
    if not queue_dir.startswith(SESS_DIRNAME_QUEUE):
        queue_dir = os.path.join(queue_dir, SESS_DIRNAME_QUEUE)
    try:
        return str(next(Path(queue_dir).glob("id:{:06d}*".format(id_no))))
    except StopIteration:
        return None

def input_id(input_path):
    input_name = os.path.basename(input_path)
    assert(input_name.startswith("id:"))
    return int(input_name[3:3+6])

def queue_or_input_path_for_name(fuzzer_dir, filename):
    try:
        return str(next(Path(fuzzer_dir).glob("*/{}".format(filename))))
    except StopIteration:
        return None

def is_trace_filename(filename):
    return any([filename.startswith(prefix) for prefix in TRACE_FILENAME_PREFIXES])

def project_base(path):
    if not os.path.exists(path):
        print("[project_base] [-] base path does not exist")
        return None
    path = os.path.abspath(path)

    while path:
        # Search for different names to be more forgiving with partially copied projects
        for name in (PIPELINE_DIRNAME_CONFIG_SNIPPETS, "main001", PIPELINE_DIRNAME_MMIO_STATES, PIPELINE_DIRNAME_STATS):
            if os.path.exists(os.path.join(path, name)):
                return path
        path, filename = os.path.split(path)
        if path == "/" and not filename:
            break

    return None

def id_from_path(path):
    """
    Extract the id from a directory (main or fuzzer)
    """
    _, dirname = os.path.split(path)
    for prefix in (SESS_NAME_PREFIX_MAIN, SESS_DIRNAME_FUZZER_INST_PREFIX):
        if dirname.startswith(prefix):
            return int(dirname[len(prefix):])

    assert False

def get_fuzzer_from_input(file):
    return file.split("/")[-3]

def get_main_from_input(file):
    return file.split("/")[-5]


def determine_fuzzers_dirs_for_main_dir(main_dir):
    return glob.glob(main_dir + "/fuzzers/*")


def main_and_fuzzer_number(path):
    """ Try to find the main and fuzzer ids for the given path.

    Searches for fuzzer and main directories in parent directories of the path.
    If no such directories is found, None is given.

    returns (main_id, fuzzer_id)
    """
    assert os.path.exists(path)
    path = os.path.abspath(path)
    main_id, fuzzer_id = None, None

    if os.path.isdir(path):
        leftover_path = path
    else:
        leftover_path, _ = os.path.split(os.path.abspath(path))

    while True:
        parent_path, dirname = os.path.split(leftover_path)

        if dirname.startswith(SESS_NAME_PREFIX_MAIN):
            main_id = id_from_path(dirname)
            # main dir is above fuzzer dir, so stop search
            break

        if dirname.startswith(SESS_DIRNAME_FUZZER_INST_PREFIX) and not dirname.startswith(SESS_DIRNAME_FUZZERS):
            fuzzer_id = id_from_path(dirname)

        if parent_path == leftover_path:
            break
        leftover_path = parent_path

    return main_id, fuzzer_id

def latest_main_dir(project_base_path):
    return main_dirs_for_proj(project_base_path)[-1]

def get_sha1_from_file(file):
    import hashlib
    sha1 = hashlib.sha1()
    BLOCK_SIZE = 65536
    with open(file, "rb") as f:
        fb = f.read(BLOCK_SIZE)
        while len(fb) > 0:
            sha1.update(fb)
            fb = f.read(BLOCK_SIZE)
    return sha1.hexdigest()


def find_modeling_venv():
    """
    In an attempt to reduce virtualenv-induced headaches, we try
    to do the user a favor and find the modeling virtualenv for
    them in different places:
    1. WORKON environment variable
    2. docker default install location
    3. user's home dir
    4. sudoing user's home dir

    Returns the full path to the modeling virtualenv.
    """
    dyn_paths = []
    venv_base = os.environ.get(ENV_VAR_WORKON_HOME)
    if venv_base:
        dyn_paths.append(os.path.join(venv_base, VENV_DIRNAME))

    # Look for the sudoer's home dir
    sudoing_user = os.environ.get('SUDO_USER')
    if sudoing_user:
        dyn_paths.append(os.path.join("/home", sudoing_user, VENV_DIRNAME))

    for venv_base in dyn_paths+VENV_SEARCH_PATHS:
        modeling_venv_path = os.path.join(venv_base, VENV_NAME_MODELING)
        if os.path.exists(modeling_venv_path):
            return modeling_venv_path

    raise Exception("Modeling venv could not be resolved. L")

def class_path(c):
    return c.__module__ + "." + c.__qualname__
