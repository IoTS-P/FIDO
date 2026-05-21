import glob
import hashlib
import os
import queue
import shutil
import time
from copy import deepcopy
from pathlib import Path
from queue import Queue

from fuzzware_harness.globs import (MMIO_HOOK_MMIO_ALL_ADDRS,
                                    MMIO_HOOK_PC_ALL_ACCESS_SITES)
from fuzzware_harness.tracing.serialization import (parse_bbl_set,
                                                    parse_mmio_set)
from fuzzware_harness.util import (_merge_dict, load_config_deep,
                                   parse_address_value, parse_symbols,
                                   resolve_region_file_paths, closest_symbol)
from watchdog.observers import Observer

from . import util
from .const import (CONFIG_UPDATE_FORCE_FUZZER_RESTART_LIMIT,
                    CONFIG_UPDATE_MIN_TIME_SINCE_NEW_BB_DISCOVERY,
                    DEFAULT_IDLE_BBL, EVENT_MIN_WAIT, IDLE_BUSYLOOP_SLEEP,
                    IDLE_COUNT_HOUSEKEEPING, LOOP_COUNT_HOUSEKEEPING,
                    MAX_NUM_DEAD_FUZZER_RESTARTS, MAX_NUM_MODELS_PER_PC,
                    FIRST_STAT_PRINT_DELAY, STAT_PRINT_INTERVAL)
from .logging_handler import logging_handler
from .naming_conventions import *  # pylint: disable=wildcard-import
from .observers.new_config_snippet_handler import NewConfigSnippetHandler
from .observers.new_mmio_state_handler import NewMmioStateHandler
from .run_target import run_target
from .session import Session
from .util.config import (add_config_entries, merge_config_file_into,
                          save_config)
from .util.eval_utils import add_input_file_time_entry, parse_valid_bb_file, parse_milestone_bb_file
from .util.trace_inspection import (bbl_set_contains,
                                    mmio_set_contains_one_context)
from .workers.pool import WorkerPool

logger = logging_handler().get_logger("pipeline")

class Pipeline:
    # Base configs
    parent_dir: str
    name: str
    base_inputs: str
    num_main_fuzzer_procs: int
    booted_bbl: int
    boot_required_bbls: set
    boot_avoided_bbls: set
    groundtruth_valid_basic_blocks: set
    groundtruth_milestone_basic_blocks: set

    # Runtime state
    start_time: int
    stop_time: int
    worker_pool: WorkerPool

    queue_fuzz_inputs: Queue
    queue_traces: Queue
    queue_mmio_states: Queue
    queue_config_snippets: Queue

    # Pipeline-scoped observer singletons
    config_snippet_observer: Observer
    mmio_state_observer: Observer

    sessions: None  # dict[name]->Session

    shutdown_requested: bool

    # Analysis result state
    # a set of (pc_addr, mmio_addr) address pairs which have already been modeled
    mmio_access_contexts = set()
    num_models_per_pc = {}

    # We keep input hashes local to each fuzzer instance as equal inputs mean very different things based on configuration
    # {session_name: set()}
    known_input_hashes = {}
    visited_translation_blocks = set()
    visited_valid_basic_blocks = set()
    visited_milestone_basic_blocks = set()

    # While we initially follow the non-configured fuzzing approach, we then start new fuzzer iterations on triggers
    curr_main_sess_index = 0

    # File handles to write status information
    warnings_file = None
    input_creation_times_file = None
    job_timings_file = None
    seen_rel_input_paths = set()

    @property
    def base_dir(self):
        return os.path.join(self.parent_dir, self.name)

    @property
    def mmio_states_dir(self) -> str:
        return os.path.join(self.base_dir, PIPELINE_DIRNAME_MMIO_STATES)

    @property
    def config_snippets_dir(self) -> str:
        return os.path.join(self.base_dir, PIPELINE_DIRNAME_CONFIG_SNIPPETS)

    @property
    def stats_dir(self) -> str:
        return os.path.join(self.base_dir, PIPELINE_DIRNAME_STATS)

    @property
    def mmio_model_config_path(self) -> str:
        return os.path.join(self.base_dir, PIPELINE_FILENAME_MMIO_MODEL_CFG)

    @property
    def exit_at_config_path(self) -> str:
        return os.path.join(self.base_dir, PIPELINE_FILENAME_EXIT_AT_CFG)

    @property
    def main_config_snippets_path(self) -> str:
        return os.path.join(self.base_dir, PIPELINE_FILENAME_MAIN_CFG_SNIPPETS)

    @property
    def warnings_file_path(self) -> str:
        return os.path.join(self.base_dir, PIPELINE_FILENAME_WARNINGS)

    @property
    def valid_basic_block_list_path(self) -> str:
        return valid_basic_block_list_path_for_proj(self.base_dir)

    @property
    def milestone_basic_block_list_path(self) -> str:
        return milestone_basic_block_list_path_for_proj(self.base_dir)

    def add_warning_line(self, line):
        # Create warnings file on-demand
        if self.warnings_file is None:
            self.warnings_file = open(self.warnings_file_path, "w")

        self.warnings_file.write(line+"\n")
        self.warnings_file.flush()

    @staticmethod
    def sess_key_for_ind(sess_ind) -> str:
        return SESS_NAME_PREFIX_MAIN + "{:03d}".format(sess_ind)

    @property
    def curr_main_sess_key(self) -> str:
        return self.sess_key_for_ind(self.curr_main_sess_index)

    @property
    def curr_main_config_path(self) -> str:
        return os.path.join(self.base_dir, self.sessions[self.curr_main_sess_key].config_path)

    @property
    def curr_main_session(self) -> Session:
        return self.sessions[self.curr_main_sess_key]

    @property
    def job_timings_file_path(self) -> str:
        return job_timings_file_path(self.base_dir)

    @property
    def input_creation_timings_path(self) -> str:
        return input_creation_timings_path(self.base_dir)

    @property
    def logs_dir(self) -> str:
        return os.path.join(self.base_dir, PIPELINE_DIRNAME_LOGS)

    def log_input_creation_time(self, input_path):
        relpath = Path(input_path).relative_to(self.base_dir)
        if relpath in self.seen_rel_input_paths:
            return

        self.seen_rel_input_paths.add(relpath)
        last_mod_time = os.stat(input_path).st_ctime
        seconds_from_start = max(round(last_mod_time - self.start_time), 0)

        add_input_file_time_entry(self.input_creation_times_file, seconds_from_start, str(relpath))
        self.input_creation_times_file.flush()

    def get_logfile_path(self, log_name) -> str:
        return os.path.join(self.logs_dir, log_name + ".log")

    @staticmethod
    def wait_event_timeout(event_time):
        diff = EVENT_MIN_WAIT - (time.time() - event_time)
        if diff > 0:
            time.sleep(diff)
            return True
        return False

    def check_emulator_dry(self):
        dry_input = empty_input_path(self.base_dir)
        Path(dry_input).touch()
        if not os.path.exists(dry_input):
            logger.error("Failed to create input for dry run!")
            exit(1)
        logger.info("Dry-running emulator to check functionality..\n")
        if run_target(self.base_config_path, dry_input, ["-v"]) != 0:
            logger.error("Failed to perform emulator dry run: Emulator status code != 0")
            exit(1)
        logger.info("Emulator dry-run successful!")
        os.remove(dry_input)

    def parse_pipeline_yml_config(self, full_config):
        self.boot_avoided_bbls = set()
        self.boot_required_bbls = set()
        boot_config = full_config.get(CONFIG_ENTRY_CATEGORY_BOOT)
        if boot_config:
            boot_required_bbls = boot_config.get(CONFIG_ENTRY_NAME_BOOT_REQUIRED)
            if boot_required_bbls:
                self.boot_required_bbls = set(map(lambda v: parse_address_value(self.symbols, v)&(~1), boot_required_bbls))
            boot_avoided_bbls = boot_config.get(CONFIG_ENTRY_NAME_BOOT_AVOID) or boot_config.get(CONFIG_ENTRY_NAME_BOOT_BLACKLISTED)
            if boot_avoided_bbls:
                self.boot_avoided_bbls = set(map(lambda v: parse_address_value(self.symbols, v)&(~1), boot_avoided_bbls))

            if self.booted_bbl == DEFAULT_IDLE_BBL:
                self.booted_bbl = parse_address_value(self.symbols, boot_config[CONFIG_ENTRY_NAME_BOOT_TARGET]) & (~1)
            logger.debug("Parsed boot config. Booted bbl: 0x{:08x}".format(self.booted_bbl))
            logger.debug("Avoid list: " + " ".join([hex(addr) for addr in self.boot_avoided_bbls]))
            logger.debug("Required: " + " ".join([hex(addr) for addr in self.boot_required_bbls]))

    def parse_ground_truth_files(self):
        valid_bb_list_path = self.valid_basic_block_list_path
        if os.path.exists(valid_bb_list_path):
            self.groundtruth_valid_basic_blocks = parse_valid_bb_file(valid_bb_list_path)

        milestone_bb_list_path = self.milestone_basic_block_list_path
        if os.path.exists(milestone_bb_list_path):
            self.groundtruth_milestone_basic_blocks = parse_milestone_bb_file(milestone_bb_list_path)

    def __init__(self, parent_dir, name, base_inputs, num_main_fuzzer_procs, disable_modeling=False, write_worker_logs=False, do_full_tracing=False, config_name=SESS_FILENAME_CONFIG, timeout_seconds=0, use_aflpp=False):
        self.booted_bbl = DEFAULT_IDLE_BBL
        self.disable_modeling = disable_modeling
        self.shutdown_requested = False
        self.sessions = {}
        self.parent_dir = parent_dir
        self.name = name
        self.num_main_fuzzer_procs = num_main_fuzzer_procs
        self.generic_inputs_dir = base_inputs
        self.do_full_tracing = do_full_tracing
        self.num_required_traces = len(SET_TRACE_FILENAME_PREFIXES) if not do_full_tracing else len(TRACE_FILENAME_PREFIXES) - 1
        self.base_config_path = os.path.join(self.parent_dir, config_name)
        self.groundtruth_valid_basic_blocks = None
        self.groundtruth_milestone_basic_blocks = None
        self.stop_time = None
        self.use_aflpp = use_aflpp

        if not os.path.isfile(self.base_config_path):
            logger.error(f"Could not find config file: {self.base_config_path}. We are probably not in a target directory. Exiting...")
            exit(1)

        self.queue_fuzz_inputs = Queue()
        self.queue_traces = Queue()
        self.queue_mmio_states = Queue()
        self.queue_config_snippets = Queue()

        self.create_dirs()
        self.check_emulator_dry()
        logger.info("Adding pipeline level observers")
        self.add_mmio_state_observer()
        self.add_config_snippets_observer()

        logger.info("Initializing worker pool")
        self.worker_pool = WorkerPool(self, write_logs=write_worker_logs)

        # Add planned runtime to main logs directory
        self.runtime_log_create(timeout_seconds)

        config_map = load_config_deep(self.base_config_path)
        if not config_map:
            logger.error(f"Could not load config from file {self.base_config_path} (file exists), exiting..")
            exit(1)

        resolve_region_file_paths(self.base_config_path, config_map)
        config_map = self.make_directory_self_contained(config_map)

        if 'include' in config_map:
            del config_map['include']

        new_config_path = os.path.join(self.base_dir, SESS_DIRNAME_NECESSARY_FILES ,os.path.basename(self.base_config_path))
        save_config(config_map, new_config_path)
        assert os.path.isfile(new_config_path)

        # get pre-configured MMIO access contexts from configuration
        if 'mmio_models' in config_map:
            for _, entry_list in config_map['mmio_models'].items():
                for entry in entry_list.values():
                    # Skip unexpected / custom entries
                    try:
                        pc = entry.get('pc', MMIO_HOOK_PC_ALL_ACCESS_SITES)
                    except AttributeError:
                        continue
                    self.mmio_access_contexts.add((pc, entry['addr']))
                    if pc != MMIO_HOOK_PC_ALL_ACCESS_SITES:
                        self.num_models_per_pc[pc] = self.num_models_per_pc.get(pc, 0) + 1

        self.symbols, self.syms_by_addr = parse_symbols(config_map)
        self.default_config_map = config_map
        self.parse_pipeline_yml_config(config_map)
        self.parse_ground_truth_files()

    def request_shutdown(self):
        logger.info("Shutdown requested!")
        self.shutdown_requested = True

    def create_dirs(self):
        if os.path.exists(self.base_dir):
            logger.warning("Found an existing project directory under {}. Moving it now".format(self.base_dir))

            backup_dirname = self.base_dir + "_old"
            if os.path.exists(backup_dirname):
                logger.warning("Removing old backed up project: {}".format(backup_dirname))
                shutil.rmtree(backup_dirname)

            shutil.move(self.base_dir, backup_dirname)
            if os.path.isdir(self.base_dir):
                logger.error("Could not move previous project dir. Still in there?")
                exit(-1)

        os.mkdir(self.base_dir)
        os.mkdir(self.mmio_states_dir)
        os.mkdir(self.config_snippets_dir)
        os.mkdir(self.logs_dir)
        os.mkdir(necessary_data_dir(self.base_dir))
        os.mkdir(self.stats_dir)
        self.input_creation_times_file = open(self.input_creation_timings_path, "w")
        self.job_timings_file = open(self.job_timings_file_path, "w")

        logger.set_output_file(self.base_dir, 'pipeline')
        logger.info(f"logging pipeline output to: {logger.output_file}.log")

    #Makes the directory self contained by copying the necessary files and adjusting the paths inside the provided config_map
    #
    #returns adjusted config_map
    def make_directory_self_contained(self, config_map):
        (files_to_copy, config_map) = self.find_necessary_files(config_map)
        self.copy_necessary_files(files_to_copy)
        return config_map

    # We store the planned run time as well as actual start time
    def runtime_log_create(self, planned_runtime):
        with open(runtime_log_path_for_proj(self.base_dir), "w") as f:
            f.write(f"planned_run_time: {planned_runtime:d}\n")
            f.write(f"start_epoch_seconds: {int(time.time()):d}\n")

    # Append end time to log file
    def runtime_log_add_end_time(self):
        if self.stop_time is None:
            self.stop_time = int(time.time())

            with open(runtime_log_path_for_proj(self.base_dir), "a") as f:
                f.write(f"end_epoch_seconds: {self.stop_time:d}\n")

    #Iterates through config_map searching for files we need to copy.
    #Adjusts paths inside the config_map.
    #
    #returns list of files we need to copy and adjusted config_map
    def find_necessary_files(self, config_map):
        files_to_copy = []

        # Copy ground truth files such as a basic block valid list or checkpoints
        for filename in STATS_GROUND_TRUTH_FILES:
            valid_bbs_path = Path(self.base_config_path).parent.joinpath(filename)
            if valid_bbs_path.exists():
                files_to_copy.append(str(valid_bbs_path))

        for item in ['memory_map']:
            for name, entry in config_map[item].items():
                for identifier in entry:
                    if identifier == 'file':
                        if os.path.isabs(entry['file']):
                            filename = entry['file']
                            files_to_copy.append(filename)
                            config_map[item][name]['file'] = os.path.join("../data/", os.path.basename(entry['file']))
                        else:
                            # the original config assumes the base dir, we are now in <base>/fuzzware-project/mainXXX
                            config_map[item][name]['file'] = os.path.join("../data/", entry['file'])
                            filename = os.path.basename(entry['file'])
                            files_to_copy.append(os.path.join(self.parent_dir, filename))

                        associated_elf = filename[:-4] + ".elf"
                        if os.path.isfile(associated_elf):
                            files_to_copy.append(associated_elf)
        return (files_to_copy, config_map)

    #Copies the provided files to the "data"-directory inside the project-folder.
    def copy_necessary_files(self, files_to_copy):
        data_dir = necessary_data_dir(self.base_dir)
        for file in files_to_copy:
            destination = data_dir.joinpath(os.path.basename(file))
            shutil.copyfile(file, destination)
            assert os.path.isfile(destination)

    def add_mmio_state_observer(self):
        observed_dir = self.mmio_states_dir
        logger.debug("Observing mmio states dir: {}".format(observed_dir))
        observer = Observer()
        observer.schedule(NewMmioStateHandler(self.queue_mmio_states), path=observed_dir)
        self.mmio_state_observer = observer
        observer.start()

    def add_config_snippets_observer(self):
        observed_dir = self.config_snippets_dir
        logger.debug("Observing config snippets dir: {}".format(observed_dir))
        observer = Observer()
        observer.schedule(NewConfigSnippetHandler(self.queue_config_snippets), path=observed_dir)
        self.config_snippet_observer = observer
        observer.start()

    def shutdown(self):
        self.worker_pool.shutdown(hard=True)

        self.runtime_log_add_end_time()

        for session in self.sessions.values():
            session.shutdown(hard=True)

        # close files
        if self.warnings_file is not None:
            self.warnings_file.close()
        self.input_creation_times_file.close()
        self.job_timings_file.close()

    def is_successfully_booted(self, bbl_set):
        # Has booted basic block config and that basic block is hit
        return self.booted_bbl != DEFAULT_IDLE_BBL and (self.booted_bbl in bbl_set) and (
            # And no blacklist addresses found and all whitelist addresses in bbl set
            (not self.boot_avoided_bbls & bbl_set) and \
                (not self.boot_required_bbls - bbl_set)
        )

    def choose_next_session_inputs(self, config_map):
        """
        Determines different sets of input file paths, ordered by desirability

        Returns a list of lists of input paths to try as fuzzer base input seeds.
        """

        # Most desirable
        new_mmio_and_boot = []
        # At least they boot or discover new MMIO vars
        new_mmio_or_boot = []
        # All unique inputs
        unique = []
        if self.curr_main_sess_index != 1:
            # Follow-up session, select input files from existing fuzzer session
            # 1. collect all new config snippets (compare previous session config.yml to new session config_map) and get their context tuples (pc, lr)
            # 2. make sure not include duplicates
            # 3. find all input files which include accesses to any newly modeled MMIO accesses
            # 4. find all input files which contain the booted state in their bbls

            prev_session = self.sessions[self.sess_key_for_ind(self.curr_main_sess_index-1)]
            previous_config_map = load_config_deep(prev_session.config_path)

            old_contexts = util.config.get_modeled_mmio_contexts(previous_config_map)
            new_contexts = util.config.get_modeled_mmio_contexts(config_map) - old_contexts

            input_md5s = set()
            for fuzzer_no in range(1, self.num_main_fuzzer_procs+1):
                for input_path in prev_session.fuzzer_input_paths(fuzzer_no):
                    with open(input_path, "rb") as f:
                        new_hash = hashlib.md5(f.read()).digest()
                    if new_hash not in input_md5s:
                        input_md5s.add(new_hash)
                    else:
                        continue

                    _, _, _, bbl_set_path, mmio_set_path, _ = trace_paths_for_input(input_path)
                    if not os.path.isfile(bbl_set_path):
                        if self.num_main_fuzzer_procs == 1:
                            self.add_warning_line("[add_main_session] Could not find trace files for input path '{}'".format(input_path))
                        continue
                    triggers_boot = self.booted_bbl == DEFAULT_IDLE_BBL or bbl_set_contains(bbl_set_path, self.booted_bbl)
                    discovers_new_mmio = mmio_set_contains_one_context(mmio_set_path, new_contexts)
                    if discovers_new_mmio:
                        new_mmio_or_boot.append(input_path)
                        if triggers_boot:
                            new_mmio_and_boot.append(input_path)
                    elif triggers_boot:
                        # No new MMIO, but boot
                        new_mmio_or_boot.append(input_path)
                    unique.append(input_path)

        generic = list(glob.glob(self.generic_inputs_dir+"/*"))
        input_candidate_lists = [new_mmio_and_boot, new_mmio_or_boot, unique, generic]

        # Also add default inputs as last entry in case it is not already part of the list
        if os.path.abspath(self.generic_inputs_dir) != default_base_input_dir():
            input_candidate_lists.append(list(glob.glob(default_base_input_dir()+"/*")))

        return [l for l in input_candidate_lists if l]

    def add_main_session(self, prefix_input_candidate=None):
        config_map = deepcopy(self.default_config_map)
        # merge into the config map all other optional config files: mmio, exit, main_snippets
        mmio_model_config_map = load_config_deep(self.mmio_model_config_path)

        if mmio_model_config_map:
            # do this by merging conflicts (see persist_results.py)
            if 'mmio_models' not in config_map:
                config_map['mmio_models'] = {}
            add_config_entries(config_map['mmio_models'], [mmio_model_config_map['mmio_models']])

        exitat_config_map = load_config_deep(self.exit_at_config_path)
        if exitat_config_map:
            # merge exit_at configs into base file
            # do this by appending own exit_at blocks to existing list
            if 'exit_at' in config_map:
                for new_exitat_name, new_exitat_bbl in exitat_config_map['exit_at'].items():
                    if new_exitat_bbl not in config_map['exit_at'].values():
                        config_map['exit_at'][new_exitat_name] = new_exitat_bbl
            else:
                config_map['exit_at'] = exitat_config_map['exit_at']

        # Main config snippets are merged in by recursive merging
        _merge_dict(config_map, load_config_deep(self.main_config_snippets_path))

        # Before adding the new session, get the possibly previously used prefix path
        is_previously_used_prefix = False
        if self.curr_main_sess_index and self.curr_main_session.prefix_input_path:
            is_previously_used_prefix = True
            prefix_input_candidate = self.curr_main_session.prefix_input_path

        self.curr_main_sess_index += 1
        self.sessions[self.curr_main_sess_key] = Session(self, self.curr_main_sess_key, self.num_main_fuzzer_procs, config_map)
        self.known_input_hashes[self.curr_main_sess_key] = set()

        # Try different sets of inputs in order of quality
        start_success = False
        for input_path_list in self.choose_next_session_inputs(config_map):
            # We have previous inputs, carry them over
            logger.debug("Copying over {} inputs".format(len(input_path_list)))

            new_sess_inputs_dir = self.curr_main_session.base_input_dir
            os.mkdir(new_sess_inputs_dir)
            for path in input_path_list:
                shutil.copy2(path, new_sess_inputs_dir)

            self.curr_main_session.minimize_inputs(prefix_candidate_path=prefix_input_candidate, is_previously_used_prefix=is_previously_used_prefix)
            # Try the inputs
            if self.curr_main_session.start_fuzzers():
                start_success = True
                break
            self.curr_main_session.clear_dirs()

        if not start_success:
            raise Exception("Fuzzer initialization failed for all inputs seed lists")

    def handle_queue_forever(self):
        idle_count, loop_count = 0, 0
        num_dead_fuzzer_restarts = 0
        num_config_updates = 0 # Types of config updates, new/modified: 1. MMIO models, 2. exit-at, 3. state, 4. systick enabled
        restart_pending = False
        pending_prefix_candidate = None
        time_latest_new_basic_block = None

        # {input_path: {PREFIX_NAME: trace_path}}
        available_trace_paths_for_input = {}
        current_time = time.time()
        while True:
            if self.shutdown_requested and not restart_pending:
                num_config_updates += 1
                self.curr_main_session.kill_fuzzers()
                restart_pending = True
            loop_count += 1

            # First wait a bit and then start printing stats regularly
            now = time.time()
            if now - self.start_time > FIRST_STAT_PRINT_DELAY and now - current_time > STAT_PRINT_INTERVAL:
                current_time = now
                self.log_stats()

            # Make sure trace jobs are created as soon as possible
            for _ in range(50):
                try:
                    event_time, fuzz_input_path = self.queue_fuzz_inputs.get_nowait()
                except queue.Empty:
                    break
                had_to_wait = self.wait_event_timeout(event_time)
                self.log_input_creation_time(fuzz_input_path)

                _, session_name, fuzzer_instance_name, _, input_filename = get_input_path_components(fuzz_input_path)

                with open(fuzz_input_path, "rb") as f:
                    new_hash = hashlib.md5(f.read()).digest()

                if new_hash not in self.known_input_hashes[session_name]:
                    logger.debug(f"New Fuzzing input. {session_name} -> {fuzzer_instance_name}: {input_filename}")
                    idle_count = 0
                    self.known_input_hashes[session_name].add(new_hash)
                    available_trace_paths_for_input[fuzz_input_path] = {}
                    self.worker_pool.enqueue_job_trace_gen(fuzz_input_path)

                if had_to_wait:
                    break

            try:
                event_time, mmio_state_path = self.queue_mmio_states.get_nowait()
                idle_count = 0
                self.wait_event_timeout(event_time)
                mmio_state_filename = os.path.basename(mmio_state_path)
                logger.debug(f"Got MMIO state: {mmio_state_filename}")
                if not self.disable_modeling:
                    self.worker_pool.enqueue_job_analyze_model(mmio_state_filename, mmio_state_path)
                    num_config_updates += 1
            except queue.Empty:
                pass

            try:
                event_time, config_path = self.queue_config_snippets.get_nowait()
                idle_count = 0
                self.wait_event_timeout(event_time)
                config_snippet_filename = os.path.basename(config_path)
                logger.info(f"New MMIO model: {config_snippet_filename}")

                merge_config_file_into(self.mmio_model_config_path, config_path)
            except queue.Empty:
                pass

            try:
                event_time, trace_file_path = self.queue_traces.get_nowait()
                input_file_path = input_for_trace_path(trace_file_path)
                prefix = trace_prefix_for_path(trace_file_path)

                # Trace files can show up after input has already been removed. Skip those cases
                if input_file_path in available_trace_paths_for_input:
                    available_trace_paths_for_input[input_file_path][prefix] = trace_file_path

                    # Make sure we have all traces ready before accessing them
                    if len(available_trace_paths_for_input[input_file_path]) == self.num_required_traces:
                        # All traces ready. Process now
                        idle_count = 0
                        self.wait_event_timeout(event_time)
                        logger.debug(f"Processing traces for input {input_file_path}")

                        # Pop traces and process them
                        traces_per_prefix = available_trace_paths_for_input.pop(input_file_path)

                        trace_filename = os.path.basename(trace_file_path)
                        input_filename = get_input_filename(trace_file_path)
                        input_file_path = input_for_trace_path(trace_file_path)

                        #### Set-based Processing
                        bbl_set = set(parse_bbl_set(traces_per_prefix[PREFIX_BASIC_BLOCK_SET]))
                        mmio_set_entries = parse_mmio_set(traces_per_prefix[PREFIX_MMIO_SET])

                        logger.debug("Looking at new translation block set")
                        new_bbs = bbl_set - self.visited_translation_blocks
                        if new_bbs:
                            logger.info(f"Found {len(new_bbs)} new translation / basic block{'s' if len(new_bbs) > 1 else ''}!")
                            time_latest_new_basic_block = time.time()
                            for pc in new_bbs:
                                sym = closest_symbol(self.syms_by_addr, pc)[0]
                                sym_suffix = ""
                                if sym:
                                    sym_suffix=f" ({sym})"
                                if self.groundtruth_valid_basic_blocks and pc in self.groundtruth_valid_basic_blocks:
                                    self.visited_valid_basic_blocks.add(pc)
                                    logger.info(f"New basic block: 0x{pc:08x}{sym_suffix}")
                                else:
                                    logger.info(f"New translation block: 0x{pc:08x}{sym_suffix}")
                                if self.groundtruth_milestone_basic_blocks and pc in self.groundtruth_milestone_basic_blocks:
                                    logger.info(f"Discovered milestone basic block: 0x{pc:08x}{sym_suffix}")
                                    self.visited_milestone_basic_blocks.add(pc)
                            self.visited_translation_blocks |= new_bbs

                        if (not (self.curr_main_session.prefix_input_path or pending_prefix_candidate)) and self.is_successfully_booted(bbl_set):
                            logger.info("FOUND MAIN ADDRESS for trace file: '{}'".format(trace_filename))
                            pending_prefix_candidate = input_for_trace_path(trace_file_path)
                            restart_pending = True
                            self.curr_main_session.kill_fuzzers()

                        logger.debug("Looking at new MMIO access set")
                        # For every new mmio access trace we get, trigger state generation for unique pc/mmio_addr pairs
                        new_pairs = []
                        for pc, address, access_mode in mmio_set_entries:
                            if (pc, address) not in self.mmio_access_contexts and \
                                (MMIO_HOOK_PC_ALL_ACCESS_SITES, address) not in self.mmio_access_contexts and \
                                    (pc, MMIO_HOOK_MMIO_ALL_ADDRS) not in self.mmio_access_contexts:
                                self.mmio_access_contexts.add((pc, address))
                                self.num_models_per_pc[pc] = self.num_models_per_pc.get(pc, 0) + 1

                                if access_mode == "r" and self.num_models_per_pc[pc] <= MAX_NUM_MODELS_PER_PC:
                                    new_pairs.append((pc, address))
                        if new_pairs:
                            logger.debug("Enqueuing new mmio access pairs for state generation: {}".format(new_pairs))
                            self.worker_pool.enqueue_job_gen_mmio_states(input_file_path, new_pairs)
            except queue.Empty:
                pass

            if idle_count != 0:
                time.sleep(IDLE_BUSYLOOP_SLEEP)

                if idle_count > IDLE_COUNT_HOUSEKEEPING or (loop_count % LOOP_COUNT_HOUSEKEEPING == 0):
                    self.worker_pool.collect_job_timings(LOOP_COUNT_HOUSEKEEPING // 2 if idle_count < IDLE_COUNT_HOUSEKEEPING else -1)
                    self.worker_pool.check_running_procs()

                    # if a restart is pending and nothing has happened for a small amount of time, check jobs
                    if restart_pending:
                        if not self.worker_pool.jobs:
                            if self.shutdown_requested:
                                return
                            # no jobs are present, we can fully restart now
                            restart_pending, num_config_updates = False, 0
                            self.curr_main_session.shutdown()
                            self.add_main_session(pending_prefix_candidate)
                            pending_prefix_candidate = None
                            time_latest_new_basic_block = None
                        else:
                            if idle_count % 10 == 0:
                                logger.info("Waiting for leftover jobs ({}) to finish...".format(len(self.worker_pool.jobs)))
                                self.worker_pool.check_lost_jobs()
                    else:
                        # Check fuzzer process liveness
                        if not self.curr_main_session.is_alive():
                            dead_instance_ids = [i + 1 for i in self.curr_main_session.dead_fuzzer_instance_indices()]
                            self.add_warning_line(f"[WARNING] Fuzzer instances {dead_instance_ids} in session {self.curr_main_sess_index} died, starting new main session, now at restart {num_dead_fuzzer_restarts+1} of {MAX_NUM_DEAD_FUZZER_RESTARTS}")

                            # Fuzzer instance was killed or died
                            if num_dead_fuzzer_restarts < MAX_NUM_DEAD_FUZZER_RESTARTS:
                                # We got tries left. Log warning and restart fuzzer instance
                                num_dead_fuzzer_restarts += 1
                                self.curr_main_session.kill_fuzzers()
                                restart_pending = True
                            else:
                                logger.error("Too many fuzzer sessions died, exiting. Check for bogus MMIO accesses created from fuzzer-controlled firmware execution.")
                                self.add_warning_line("[ERROR] Too many fuzzer sessions died, exiting")
                                self.request_shutdown()

            # Do we have config updates?
            if (not restart_pending) and num_config_updates != 0 and (
                # We have a huge number of config updates
                num_config_updates >= CONFIG_UPDATE_FORCE_FUZZER_RESTART_LIMIT or (
                # Or we have a smaller number of updates, but waited for new things to happen long enough
                time_latest_new_basic_block is None or
                    (time.time() - time_latest_new_basic_block > CONFIG_UPDATE_MIN_TIME_SINCE_NEW_BB_DISCOVERY)
                )):
                self.curr_main_session.kill_fuzzers()
                restart_pending = True
                # After killing the fuzzers, add a temporary modeling worker to go through any leftover modeling jobs
                self.worker_pool.spawn_modeling_worker(burst=True)

            idle_count += 1

    def start(self):
        assert self.curr_main_sess_index == 0
        self.start_time = time.time()
        self.stop_time = None

        self.add_main_session()

        logger.info("Listening for new queue entries")
        self.handle_queue_forever()

    def log_stats(self):
        trace_gen_job_count = len(self.worker_pool.job_queue_trace_gen)
        model_gen_job_count = len(self.worker_pool.job_queue_modeling)
        state_gen_job_count = len(self.worker_pool.job_queue_state_gen)
        log_string = f"Current Pipeline Status (main{self.curr_main_sess_index:03d})\n"
        if self.groundtruth_valid_basic_blocks:
            num_covered_bbs, num_valid_bbs = len(self.visited_valid_basic_blocks), len(self.groundtruth_valid_basic_blocks)
            log_string += f"Basic block coverage: {num_covered_bbs} / {num_valid_bbs} ({round(num_covered_bbs/num_valid_bbs * 100, 2) }%)."
        else:
            log_string += f"Translation blocks covered (missing BB ground truth!): {len(self.visited_translation_blocks)}."

        if self.groundtruth_milestone_basic_blocks:
            num_covered_milestone_bbs, num_milestone_bbs = len(self.visited_milestone_basic_blocks), len(self.groundtruth_milestone_basic_blocks)
            log_string += f" Milestones covered: {num_covered_milestone_bbs} / {num_milestone_bbs} ({round(num_covered_milestone_bbs / num_milestone_bbs * 100, 2) }%)"

        log_string += f"\nCurrent jobs in Queue (trace gen/state gen/model gen): {trace_gen_job_count}/{state_gen_job_count}/{model_gen_job_count}\n"

        if len(self.curr_main_session.fuzzers) == 1:
            curr_execs_per_second, overall_execs_per_second = self.curr_main_session.get_execs_per_sec(1)
            curr_num_crashes = self.curr_main_session.get_num_crashes(1)
            log_string += f"Current number of crashes: {curr_num_crashes:d}\n"
            log_string += f"Current executions per second: {curr_execs_per_second:.2f} (overall: {overall_execs_per_second:.2f})\n"
        else:
            log_string += "Current fuzzer stats:\n"
            for fuzzer in self.curr_main_session.fuzzers:
                curr_execs_per_second, overall_execs_per_second = self.curr_main_session.get_execs_per_sec(fuzzer.inst_num)
                curr_num_crashes = self.curr_main_session.get_num_crashes(fuzzer.inst_num)
                log_string += f"[{fuzzer.inst_num}] crashes: {curr_num_crashes:d}. execs/second: {curr_execs_per_second:.2f} (overall: {overall_execs_per_second:.2f})\n"

        logger.info(log_string)
