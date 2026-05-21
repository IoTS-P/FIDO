import os
import shutil
import subprocess
import time
from os.path import isfile, join, exists

from fuzzware_harness.tracing.serialization import (parse_bbl_set,
                                                    parse_mmio_trace)
from watchdog.observers import Observer

from .const import MAX_FUZZER_DRYRUN_SECONDS
from .fuzzer_instance import LocalFuzzerInstance
from .logging_handler import logging_handler
from .naming_conventions import (SESS_DIRNAME_BASE_INPUTS,
                                 SESS_DIRNAME_FUZZERS,
                                 SESS_DIRNAME_TEMP_MINIMIZATION,
                                 SESS_DIRNAME_TRACES, SESS_FILENAME_CONFIG,
                                 SESS_FILENAME_EXTRA_ARGS,
                                 SESS_FILENAME_FMT_FUZZER_N,
                                 SESS_FILENAME_PREFIX_INPUT,
                                 SESS_FILENAME_PREFIX_INPUT_ORIG,
                                 SESS_FILENAME_TEMP_BBL_SET,
                                 SESS_FILENAME_TEMP_MMIO_TRACE,
                                 SESS_FILENAME_TEMP_PREFIX_INPUT,
                                 SESS_FILENAME_CUR_INPUT)
from .observers.new_fuzz_input_handler import NewFuzzInputHandler
from .observers.new_trace_file_handler import NewTraceFileHandler
from .run_fuzzer import run_corpus_minimizer
from .run_target import gen_run_arglist, run_target
from .util.config import save_config, save_extra_args
from .util.files import copy_prefix_to, first_file, prepend_to_all
from .util.eval_utils import parse_afl_fuzzer_stats
from .workers.tracegen import gen_traces

logger = logging_handler().get_logger("pipeline")


class Session:
    name: str
    parent: None  # Pipeline
    timeout: int

    # Cached here, but present by convention:
    # Everything needed in order to reproduce the exact configuration
    extra_runtime_args: list
    # prefix input representing certain state
    prefix_input_path: str

    num_fuzzer_procs: int
    fuzzers = [] # list(LocalFuzzerInstance)
    input_observer: Observer
    trace_observer: Observer

    def __init__(self, parent, name, num_fuzzers, config_map, extra_runtime_args = None):
        self.parent = parent
        self.name = name
        self.num_fuzzer_procs = num_fuzzers
        self.extra_runtime_args = list(extra_runtime_args) if extra_runtime_args is not None else []
        self.timeout = 0
        self.prefix_input_path = None
        self.input_observer = Observer()
        self.trace_observer = Observer()
        self.latest_activity = None

        assert "_" not in name

        self.create_dirs()
        self.create_files(config_map)

    @property
    def base_dir(self) -> str:
        return join(self.parent.base_dir, self.name)

    @property
    def base_input_dir(self) -> str:
        return join(self.base_dir, SESS_DIRNAME_BASE_INPUTS)

    @property
    def base_input_paths(self) -> str:
        return [f for f in os.listdir(self.base_input_dir) if isfile(join(self.base_input_dir, f))]

    @property
    def config_path(self) -> str:
        return join(self.base_dir, SESS_FILENAME_CONFIG)

    @property
    def extra_args_path(self) -> str:
        return join(self.base_dir, SESS_FILENAME_EXTRA_ARGS)

    @property
    def temp_minimization_dir(self) -> str:
        return join(self.base_dir, SESS_DIRNAME_TEMP_MINIMIZATION)

    @property
    def temp_bbl_set_path(self) -> str:
        return join(self.base_dir, SESS_FILENAME_TEMP_BBL_SET)

    @property
    def temp_mmio_trace_path(self) -> str:
        return join(self.base_dir, SESS_FILENAME_TEMP_MMIO_TRACE)

    @property
    def temp_prefix_input_path(self) -> str:
        return join(self.base_dir, SESS_FILENAME_TEMP_PREFIX_INPUT)

    def _gen_prefix_input_path(self) -> str:
        return join(self.base_dir, SESS_FILENAME_PREFIX_INPUT)

    def _gen_prefix_input_backup_path(self) -> str:
        return join(self.base_dir, SESS_FILENAME_PREFIX_INPUT_ORIG)

    def create_dirs(self):
        os.mkdir(self.base_dir)

        # In case we only have one fuzzer, the fuzzer1 dir will be passed to afl's output dir directly. Create the parent
        if self.num_fuzzer_procs == 1:
            os.mkdir(self.fuzzers_dir)

    def create_files(self, config_map):
        save_config(config_map, self.config_path)

        save_extra_args(self.extra_runtime_args, self.extra_args_path)

    def set_timeout(self, timeout):
        self.timeout = timeout

    def is_timed_out(self):
        return self.timeout != 0 and (time.time() - self.latest_activity) > self.timeout

    def tick_active(self):
        self.latest_activity = time.time()

    def start_fuzzer(self, fuzzer_num):
        fuzzer = LocalFuzzerInstance(self, fuzzer_num, use_aflpp=self.parent.use_aflpp)
        logger.info("Appending fuzzer: {}".format(fuzzer))
        self.fuzzers.append(fuzzer)
        return fuzzer.start(silent=True)

    def get_booting_prefix_size(self, input_path):
        """
        For an input file located at input_path, find the prefix size required to reach successful boot.

        If booting successful, returns the size of the input prefix.
        Otherwise, returns None
        """
        gen_traces(self.config_path, input_path, mmio_trace_path=self.temp_mmio_trace_path, bbl_set_path=self.temp_bbl_set_path, extra_args=["--exit-at", "0x{:x}".format(self.parent.booted_bbl)])
        bbl_set = set(parse_bbl_set(self.temp_bbl_set_path))
        if not self.parent.is_successfully_booted(bbl_set):
            return None

        prefix_size = None
        for _, _, _, mode, _, access_fuzz_ind, num_consumed_fuzz_bytes, _, _ in parse_mmio_trace(self.temp_mmio_trace_path)[::-1]:
            if mode == "r":
                prefix_size = access_fuzz_ind + num_consumed_fuzz_bytes
                break

        # MMIO input feeding does not represent all the ways in which input can be consumed.
        # For example, an interrupt trigger could have consumed an additional fuzz byte.
        # Now make sure we are still booting with the prefix or add input bytes as necessary.
        if prefix_size is not None:
            # Try expanding input and re-running for a number of times
            for _ in range(16):
                copy_prefix_to(self.temp_prefix_input_path, input_path, prefix_size)
                gen_traces(self.config_path, self.temp_prefix_input_path, mmio_trace_path=self.temp_mmio_trace_path, bbl_set_path=self.temp_bbl_set_path, extra_args=["--exit-at", "0x{:x}".format(self.parent.booted_bbl)])
                bbl_set = set(parse_bbl_set(self.temp_bbl_set_path))

                if self.parent.is_successfully_booted(bbl_set):
                    return prefix_size
                prefix_size += 1

        return None

    def emulator_args(self):
        return gen_run_arglist(self.config_path, self.extra_runtime_args)

    def save_prefix_input(self, file_containing_prefix, prefix_size):
        """
        Copy first prefix_size bytes of file_containing_prefix and set as the Session's new input prefix
        """
        # Backup the original file
        shutil.copyfile(file_containing_prefix, self._gen_prefix_input_backup_path())

        self.prefix_input_path = self._gen_prefix_input_path()
        copy_prefix_to(self.prefix_input_path, file_containing_prefix, prefix_size)
        if not any(['--prefix-input' in arg for arg in self.extra_runtime_args]):
            self.extra_runtime_args += ['--prefix-input', self.prefix_input_path]
            save_extra_args(self.extra_runtime_args, self.extra_args_path)

    def clear_dirs(self):
        if os.path.exists(self.base_input_dir):
            shutil.rmtree(self.base_input_dir)
        if os.path.exists(self.temp_minimization_dir):
            shutil.rmtree(self.temp_minimization_dir)

    def minimize_inputs(self, silent=False, prefix_candidate_path=None, is_previously_used_prefix=False):
        assert(prefix_candidate_path or not is_previously_used_prefix)

        # Handle cases where prefix candidate is passed
        if prefix_candidate_path:
            booting_prefix_size = self.get_booting_prefix_size(prefix_candidate_path)
            is_booted_successfully = booting_prefix_size is not None
            if is_previously_used_prefix:
                if is_booted_successfully:
                    # A previously booting prefix still boots.
                    # Set the booting prefix and prepend remainder to input files
                    self.save_prefix_input(prefix_candidate_path, booting_prefix_size)
                    prepend_to_all(self.base_input_dir, prefix_candidate_path, from_offset=booting_prefix_size)
                else:
                    # The input no longer successfully boots the image
                    # Attach the no longer booting prefix to input files and minimize without prefix
                    prepend_to_all(self.base_input_dir, prefix_candidate_path)
            else:
                if is_booted_successfully:
                    # A brand new booting input was discovered, use it as new input prefix and reset to generic inputs
                    # extract prefix from input, copy over generic base inputs
                    shutil.rmtree(self.base_input_dir)
                    shutil.copytree(self.parent.generic_inputs_dir, self.base_input_dir)
                    self.save_prefix_input(prefix_candidate_path, booting_prefix_size)
                    # No minimization or input corpus adjustment required in this case, return
                    return
        else:
            # We are currently not able to successfully boot, minimize normally
            pass

        # Perform minimization. In case an input prefix is used, this is already saved in self.extra_runtime_args
        shutil.move(self.base_input_dir, self.temp_minimization_dir)
        harness_args = self.emulator_args()

        try:
            run_corpus_minimizer(harness_args, self.temp_minimization_dir, self.base_input_dir, silent=silent, use_aflpp=self.parent.use_aflpp)
            if not os.listdir(self.base_input_dir):
                self.parent.add_warning_line("Minimization for fuzzing session '{}' had no inputs remaining, copying generic inputs.".format(self.name))
                shutil.rmtree(self.base_input_dir, True)
                shutil.copytree(self.parent.generic_inputs_dir, self.base_input_dir)
        except subprocess.CalledProcessError:
            self.parent.add_warning_line("Minimization for fuzzing session '{}' failed, copying full inputs.".format(self.name))

            # In case minimization does not work out, copy all inputs
            shutil.rmtree(self.base_input_dir, True)
            shutil.copytree(self.temp_minimization_dir, self.base_input_dir)

    def start_fuzzers(self):
        """
        Start all fuzzer instances for this session.
        Returns True, if fuzzers have been started successfully, False on errors.
        """

        queue_paths = []
        stats_paths = []
        for i in range(1, self.num_fuzzer_procs + 1):
            logger.info("Starting fuzzer number {}".format(i))
            fuzzer_dir = self.fuzzer_instance_dir(i)
            if os.path.exists(fuzzer_dir):
                shutil.rmtree(fuzzer_dir)

            if not self.start_fuzzer(i):
                logger.error("Error while starting fuzzer numer: {:d}".format(i))
            queue_paths.append(join(fuzzer_dir, "queue"))
            stats_paths.append(join(fuzzer_dir, "fuzzer_stats"))

            # Wait a bit for fuzzer to choose its CPU affinity to avoid races
            time.sleep(0.05)

        # Now wait for all the fuzzer instances to have come up
        num_tries = 0
        while any([not os.path.exists(path) for path in stats_paths]):
            num_tries += 1
            if num_tries >= 10:
                break
            logger.info("Waiting for fuzzers to have started up")
            time.sleep(1)

        time.sleep(1)
        for instance in self.fuzzers:
            fuzzer_proc_exit_status = instance.proc.poll()
            if fuzzer_proc_exit_status is not None:
                logger.error(f"Fuzzing instance: {instance} exited right after start, exiting")

                self.parent.add_warning_line("Fuzzer instance errored with code {}".format(fuzzer_proc_exit_status))
                self.kill_fuzzers()

                logger.warning(f"\n\n[TRIAGING STEP 1] Re-running fuzzer for a maximum of {MAX_FUZZER_DRYRUN_SECONDS} seconds, showing its output...")
                instance.start(silent=False)
                for _ in range(MAX_FUZZER_DRYRUN_SECONDS):
                    time.sleep(1)

                    fuzzer_proc_exit_status = instance.proc.poll()
                    if fuzzer_proc_exit_status is not None:
                        break
                instance.kill()
                logger.warning("[TRIAGING STEP 1] ... Output end")

                logger.warning("\n\n[TRIAGING STEP 2] Re-running single emulation run, showing its output...")
                run_target(self.config_path, first_file(self.base_input_dir), self.extra_runtime_args + [ "-v" ])
                logger.warning("[TRIAGING STEP 2] ... Output end\n")

                logger.warning("\n\n[TRIAGING STEP 3] Re-running single emulation run with .cur_input file, showing its output...")
                run_target(self.config_path, self.fuzzer_cur_input_path(instance.inst_num), self.extra_runtime_args + [ "-v" ])
                logger.warning("[TRIAGING STEP 3] ... Output end\n")

                return False

        logger.info("Fuzzers started up, setting up listeners for input generation")
        for fuzzer in self.fuzzers:
            self.add_input_queue_watch(fuzzer)
            self.add_trace_watch(fuzzer)
        self.input_observer.start()
        self.trace_observer.start()

        # Add the initial inputs for trace generation
        for path in queue_paths:
            for input_filename in [f for f in os.listdir(path) if isfile(join(path, f))]:
                if input_filename.startswith("id"):
                    self.parent.queue_fuzz_inputs.put((0, join(path, input_filename)))

        return True

    def dead_fuzzer_instance_indices(self):
        res = []

        for i, instance in enumerate(self.fuzzers):
            fuzzer_proc_exit_status = instance.proc.poll()
            if fuzzer_proc_exit_status is not None:
                res.append(i)

        return res

    def is_alive(self):
        for instance in self.fuzzers:
            fuzzer_proc_exit_status = instance.proc.poll()
            if fuzzer_proc_exit_status is not None:
                return False
        return True

    def kill_fuzzers(self, hard=False):
        logger.info("Killing {} fuzzer(s)".format(len(self.fuzzers)))
        while self.fuzzers:
            self.fuzzers.pop().kill()

        # As soon as fuzzers are gone, no new inputs will be generated
        if self.input_observer:
            self.input_observer.stop()
            if not hard:
                try:
                    self.input_observer.join()
                except RuntimeError:
                    pass

    def kill_observers(self, hard=False):
        logger.info("Removing observers")
        if self.input_observer:
            self.input_observer.stop()
        if self.trace_observer:
            self.trace_observer.stop()
        if not hard:
            if self.input_observer:
                try:
                    self.input_observer.join()
                except RuntimeError:
                    pass
            if self.trace_observer:
                try:
                    self.trace_observer.join()
                except RuntimeError:
                    pass
        self.input_observer = None
        self.trace_observer = None

    def shutdown(self, hard=False):
        self.kill_fuzzers(hard)
        self.kill_observers(hard)

    def add_input_queue_watch(self, fuzzer_instance):
        observed_dir = join(self.fuzzer_instance_dir(fuzzer_instance.inst_num), "queue")
        assert os.path.exists(observed_dir)
        logger.info("Observing directory '{}' now".format(observed_dir))
        self.input_observer.schedule(NewFuzzInputHandler(self.parent.queue_fuzz_inputs), path=observed_dir)

    def add_trace_watch(self, fuzzer_instance):
        observed_dir = self.fuzzer_trace_dir(fuzzer_instance.inst_num)

        # We only do this once a fuzzer is up and running
        assert os.path.exists(join(self.fuzzer_instance_dir(fuzzer_instance.inst_num), "queue"))

        # Create the trace output directory for the fuzzer
        os.mkdir(self.fuzzer_trace_dir(fuzzer_instance.inst_num))

        logger.info("Observing trace dir: {}".format(observed_dir))
        self.trace_observer.schedule(NewTraceFileHandler(self.parent.queue_traces), path=observed_dir)

    @property
    def project_dir(self) -> str:
        return self.parent.base_dir

    @property
    def fuzzers_dir(self) -> str:
        return join(self.base_dir, SESS_DIRNAME_FUZZERS)

    def fuzzer_instance_dir(self, fuzzer_no: int) -> str:
        return join(self.fuzzers_dir, SESS_FILENAME_FMT_FUZZER_N.format(fuzzer_no))

    def fuzzer_trace_dir(self, fuzzer_no: int) -> str:
        return join(self.fuzzer_instance_dir(fuzzer_no), SESS_DIRNAME_TRACES)

    def fuzzer_queue_dir(self, fuzzer_no: int) -> str:
        return join(self.fuzzer_instance_dir(fuzzer_no), 'queue')

    def fuzzer_cur_input_path(self, fuzzer_no: int) -> str:
        return join(self.fuzzer_instance_dir(fuzzer_no), SESS_FILENAME_CUR_INPUT)

    def fuzzer_input_paths(self, fuzzer_no: int):
        """
        Generates a list of input paths for the given fuzzer instance (index is 1-based as done per fuzzer naming convention)
        """
        queue_dir = self.fuzzer_queue_dir(fuzzer_no)
        return [join(queue_dir, f) for f in os.listdir(queue_dir) if f.startswith("id") and isfile(join(queue_dir, f))]

    def get_fuzzer_stats_file(self, fuzzer_no: int):
        return join(self.fuzzer_instance_dir(fuzzer_no), 'fuzzer_stats')

    def get_execs_per_sec(self, fuzzer_no: int):
        fuzzer_stats_file = self.get_fuzzer_stats_file(fuzzer_no)

        curr_execs_per_sec, overall_execs_per_sec = 0, 0
        if exists(fuzzer_stats_file):
            fuzzer_stats = parse_afl_fuzzer_stats(fuzzer_stats_file)
            try:
                curr_execs_per_sec = float(fuzzer_stats["execs_per_sec"])
                start_time = float(fuzzer_stats["start_time"])
                last_update_time = float(fuzzer_stats["last_update"])
                total_execs = float(fuzzer_stats["execs_done"])

                overall_execs_per_sec = total_execs / (last_update_time - start_time)
            except (ValueError, Exception):
                pass

        return curr_execs_per_sec, overall_execs_per_sec

    def get_num_crashes(self, fuzzer_no):
        fuzzer_stats_file = self.get_fuzzer_stats_file(fuzzer_no)

        num_crashes = 0
        if exists(fuzzer_stats_file):
            fuzzer_stats = parse_afl_fuzzer_stats(fuzzer_stats_file)
            try:
                num_crashes = int(fuzzer_stats["unique_crashes"])
            except (ValueError, Exception):
                pass

        return num_crashes
