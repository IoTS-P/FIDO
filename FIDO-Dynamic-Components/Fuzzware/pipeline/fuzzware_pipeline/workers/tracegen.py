import datetime
import os
from re import sub
import signal
import subprocess
import time
import uuid
from pathlib import Path

import rq
from fuzzware_pipeline.logging_handler import logging_handler
from rq.worker import WorkerStatus

from .. import naming_conventions as nc
from ..run_target import gen_run_arglist, run_target
from ..util.config import load_extra_args, parse_extra_args

logger = logging_handler().get_logger("tracegen")

FORKSRV_FD = 198

# Make sure these names are synchronized with the argument names below
ARGNAME_BBL_SET_PATH, ARGNAME_MMIO_SET_PATH = "bbl_set_path", "mmio_set_path"
ARGNAME_EXTRA_ARGS = "extra_args"
FORKSERVER_UNSUPPORTED_TRACE_ARGS = ("mmio_trace_path", "bbl_trace_path", "ram_trace_path")
def gen_traces(config_path, input_path, bbl_trace_path=None, ram_trace_path=None, mmio_trace_path=None, bbl_set_path=None, mmio_set_path=None, extra_args=None, silent=False, bbl_hash_path=None):
    extra_args = list(extra_args) if extra_args else []

    if bbl_trace_path is not None:
        extra_args += ["--bb-trace-out", bbl_trace_path]
    if ram_trace_path is not None:
        extra_args += ["--ram-trace-out", ram_trace_path]
    if mmio_trace_path is not None:
        extra_args += ["--mmio-trace-out", mmio_trace_path]
    if bbl_set_path is not None:
        extra_args += ["--bb-set-out", bbl_set_path]
    if mmio_set_path is not None:
        extra_args += ["--mmio-set-out", mmio_set_path]
    if bbl_hash_path is not None:
        extra_args += ["--bb-hash-out", bbl_hash_path]

    run_target(config_path, input_path, extra_args, silent=silent, stdout=subprocess.DEVNULL if silent else None, stderr=subprocess.DEVNULL if silent else None)
    return True

def batch_gen_native_traces(config_path, input_paths, extra_args=None, bbl_set_paths=None, mmio_set_paths=None, bbl_hash_paths=None, silent=False):
    """
    Utility function to generate batches of traces that the emulator
    supports native snapshotting for.
    """
    common_length = len(input_paths)

    # Spawn process, while disabling generation types where we can
    gentrace_proc = TraceGenProc(config_path, extra_args, silent=silent,
        gen_bb_set=(not bbl_set_paths) is False and not all(p is None for p in bbl_set_paths),
        gen_mmio_set=(not mmio_set_paths) is False and not all(p is None for p in mmio_set_paths),
        gen_bb_hash=(not bbl_hash_paths) is False and not all(p is None for p in bbl_hash_paths)
    )

    bbl_set_paths = bbl_set_paths or common_length * [None]
    mmio_set_paths = mmio_set_paths or common_length * [None]
    bbl_hash_paths = bbl_hash_paths or common_length * [None]

    for input_path, bbl_set_path, mmio_set_path, bbl_hash_path in zip(input_paths, bbl_set_paths, mmio_set_paths, bbl_hash_paths):
        if not gentrace_proc.gen_trace(input_path, bbl_set_path, mmio_set_path, bbl_hash_path):
            logger.error(f"Hit abrupt end while trying to execute input {input_path}")
            assert(False)

    gentrace_proc.destroy()

def gen_missing_maindir_traces(maindir, required_trace_prefixes, fuzzer_nums=None, tracedir_postfix="", log_progress=False, verbose=False, crashing_inputs=False, force_overwrite=False):
    projdir = nc.project_base(maindir)
    config_path = nc.config_file_for_main_path(maindir)
    extra_args = parse_extra_args(load_extra_args(nc.extra_args_for_config_path(config_path)), projdir)

    jobs_for_config = []
    fuzzer_dirs = nc.fuzzer_dirs_for_main_dir(maindir)

    if fuzzer_nums is not None:
        assert all(0 < i <= len(fuzzer_dirs) for i in fuzzer_nums)
        fuzzer_dirs = [fuzzer_dirs[i-1] for i in fuzzer_nums]

    can_use_native_batch = all(prefix in nc.NATIVE_TRACE_FILENAME_PREFIXES for prefix in required_trace_prefixes)
    num_gentrace_jobs = 0
    for fuzzer_dir in fuzzer_dirs:
        tracedir = fuzzer_dir.joinpath(nc.trace_dirname(tracedir_postfix, is_crash=crashing_inputs))

        # In case we have a custom tracedir postfix, we need to create directories on demand
        if not tracedir.exists():
            tracedir.mkdir()
        elif force_overwrite == True:
            # Assumption: Only files, no directories, in tracedir
            for trace in tracedir.iterdir():
                trace.unlink()

        for input_path in nc.input_paths_for_fuzzer_dir(fuzzer_dir, crashes=crashing_inputs):
            bbl_trace_path, ram_trace_path, mmio_trace_path = None, None, None
            bbl_set_path, mmio_set_path, bbl_hash_path = None, None, None
            for trace_path in nc.trace_paths_for_input(input_path):
                trace_dir, trace_name = os.path.split(trace_path)

                if tracedir_postfix:
                    trace_path = os.path.join(trace_dir+f"_{tracedir_postfix}", trace_name)

                for prefix in required_trace_prefixes:
                    if trace_name.startswith(prefix) and not os.path.exists(trace_path):
                        if prefix == nc.PREFIX_BASIC_BLOCK_TRACE:
                            bbl_trace_path = trace_path
                        elif prefix == nc.PREFIX_MMIO_TRACE:
                            mmio_trace_path = trace_path
                        elif prefix == nc.PREFIX_RAM_TRACE:
                            ram_trace_path = trace_path
                        elif prefix == nc.PREFIX_BASIC_BLOCK_SET:
                            bbl_set_path = trace_path
                        elif prefix == nc.PREFIX_MMIO_SET:
                            mmio_set_path = trace_path
                        elif prefix == nc.PREFIX_BASIC_BLOCK_HASH:
                            bbl_hash_path = trace_path
                        else:
                            assert False
                        break

            if any(p is not None for p in (bbl_trace_path, ram_trace_path, mmio_trace_path, bbl_set_path, mmio_set_path, bbl_hash_path)):
                num_gentrace_jobs += 1
                if can_use_native_batch:
                    # This is ugly, but this way we don't need to pivot the lists later
                    if not jobs_for_config:
                        jobs_for_config = [[], [], [], []]
                    jobs_for_config[0].append(input_path)
                    jobs_for_config[1].append(bbl_set_path)
                    jobs_for_config[2].append(mmio_set_path)
                    jobs_for_config[3].append(bbl_hash_path)
                else:
                    jobs_for_config.append((str(input_path), bbl_trace_path, ram_trace_path, mmio_trace_path, bbl_set_path, mmio_set_path, bbl_hash_path))

    # If we found jobs for the given config path, add them
    if not jobs_for_config:
        if log_progress:
            logger.info("No traces to generate for main path")
        return

    num_processed = 0

    start_time = time.time()
    if can_use_native_batch:
        input_paths, bbl_set_paths, mmio_set_paths, bbl_hash_paths = jobs_for_config
        batch_gen_native_traces(config_path, input_paths, extra_args, bbl_set_paths, mmio_set_paths, bbl_hash_paths, not verbose)
        if log_progress:
            logger.info(f"Generating traces took {time.time() - start_time:.02f} seconds for {len(input_paths)} input(s)")
    else:
        num_processed = 0
        for input_path, bbl_trace_path, ram_trace_path, mmio_trace_path, bbl_set_path, mmio_set_path, bbl_hash_path in jobs_for_config:
            gen_traces(str(config_path), str(input_path),
                bbl_trace_path=bbl_trace_path, ram_trace_path=ram_trace_path, mmio_trace_path=mmio_trace_path,
                bbl_set_path=bbl_set_path, mmio_set_path=mmio_set_path, bbl_hash_path=bbl_hash_path,
                extra_args=extra_args, silent=not verbose
            )
            num_processed += 1

            if log_progress:
                if num_processed > 0 and num_processed % 50 == 0:
                    time_passed = round(time.time() - start_time)
                    relative_done = (num_processed+1) / num_gentrace_jobs
                    time_estimated = round((relative_done ** (-1)) * time_passed)
                    logger.info(f"[*] Processed {num_processed}/{num_gentrace_jobs} in {time_passed} seconds. Estimated seconds remaining: {time_estimated-time_passed}")

def gen_all_missing_traces(projdir, trace_name_prefixes=None, log_progress=False, verbose=False, crashing_inputs=False, force_overwrite=False):
    if trace_name_prefixes is None:
        trace_name_prefixes = nc.TRACE_FILENAME_PREFIXES

    for maindir in nc.main_dirs_for_proj(projdir):
        gen_missing_maindir_traces(maindir, trace_name_prefixes, log_progress=log_progress, verbose=verbose, crashing_inputs=crashing_inputs, force_overwrite=force_overwrite)

def spawn_forkserver_emu_child(config_path, input_path, extra_args, silent=False):
    arg_list = gen_run_arglist(config_path, extra_args) + [input_path]

    # Set up pipes for AFL fork server communication
    control_fd_rd, control_fd_wr = os.pipe()
    status_fd_rd, status_fd_wr = os.pipe()

    os.dup2(control_fd_rd, FORKSRV_FD)
    os.dup2(status_fd_wr, FORKSRV_FD + 1)
    os.set_inheritable(FORKSRV_FD, True)
    os.set_inheritable(FORKSRV_FD + 1, True)

    # Close duplicated fds
    os.close(control_fd_rd)
    os.close(status_fd_wr)

    subprocess_env = os.environ
    subprocess_env.setdefault("__AFL_SHM_ID", "0")

    # Silence stdout/stderr if requested
    stdout, stderr = None, None
    if silent:
        stdout, stderr = subprocess.DEVNULL, subprocess.DEVNULL

    proc = subprocess.Popen(arg_list, stdout=stdout, stderr=stderr, pass_fds=[FORKSRV_FD, FORKSRV_FD + 1], env=subprocess_env)

    # Close opposing end of pipe
    os.close(FORKSRV_FD)
    os.close(FORKSRV_FD + 1)

    # Wait for emulator process to respond
    assert len(os.read(status_fd_rd, 4)) == 4

    return proc, control_fd_wr, status_fd_rd

class TraceGenProc:
    """
    Class which spawns an underlying emulator child to then generate
    traces quickly, given a stable configuration.

    This fakes the fuzzer side of the AFL fork server setup to the emulator
    so that the emulator can use snapshotting to quickly run multiple times.
    """
    uuid: str

    # Stable paths to pass arguments to emulator where we create symlinks later
    stable_input_path: Path = None
    stable_bbset_path: Path = None
    stable_bbhash_path: Path = None
    stable_mmioset_path: Path = None

    child_proc = None
    status_read_fd = None
    ctrl_write_fd = None
    config_path = None

    def __init__(self, config_path, extra_args=None, gen_bb_set=False, gen_mmio_set=False, gen_bb_hash=False, base_path="/tmp", silent=False):
        self.uuid = str(uuid.uuid4())

        self.stable_input_path = Path(os.path.join(base_path, ".trace_input_"+self.uuid))
        if gen_bb_set:
            self.stable_bbset_path = Path(os.path.join(base_path, ".trace_bbset_"+self.uuid))
        if gen_bb_hash:
            self.stable_bbhash_path = Path(os.path.join(base_path, ".trace_bbhash_"+self.uuid))
        if gen_mmio_set:
            self.stable_mmioset_path = Path(os.path.join(base_path, ".trace_mmioset_"+self.uuid))

        self.spawn_emulator_child(config_path, extra_args, gen_bb_set=gen_bb_set, gen_mmio_set=gen_mmio_set, gen_bb_hash=gen_bb_hash, silent=silent)

    def destroy(self):
        self.rm_old_links()
        self.kill_emulator_child()

    def __del__(self):
        self.destroy()

        try:
            super().__del__()
        except AttributeError:
            pass

    def spawn_emulator_child(self, config_path, extra_args=None, gen_bb_set=False, gen_mmio_set=False, gen_bb_hash=False, silent=False):
        extra_args = extra_args or []

        if gen_bb_set:
            extra_args += ["--bb-set-out", str(self.stable_bbset_path)]
        if gen_mmio_set:
            extra_args += ["--mmio-set-out", str(self.stable_mmioset_path)]
        if gen_bb_hash:
            extra_args += ["--bb-hash-out", str(self.stable_bbhash_path)]

        logger.debug(f"spawn_emulator_child setting up arguments {extra_args}")
        self.child_proc, self.ctrl_write_fd, self.status_read_fd = spawn_forkserver_emu_child(config_path, self.stable_input_path, extra_args, silent=silent)

    def kill_emulator_child(self):
        logger.debug("[Trace Gen] kill_emulator_child")
        if self.status_read_fd is not None:
            os.close(self.status_read_fd)
            os.close(self.ctrl_write_fd)
            try:
                self.child_proc.kill()
            except OSError:
                pass

            self.status_read_fd = None
            self.ctrl_write_fd = None
            self.child_proc = None

    def rm_old_links(self):
        for p in (self.stable_input_path, self.stable_bbset_path, self.stable_mmioset_path, self.stable_bbhash_path):
            if p is not None:
                try:
                    p.unlink()
                except FileNotFoundError:
                    pass

    def setup_links(self, input_path, bb_set_path=None, mmio_set_path=None, bb_hash_path=None):
        # Create Symlinks to input and output paths
        self.rm_old_links()

        # We always need an input
        self.stable_input_path.symlink_to(input_path)

        # For output paths, we may not need to create all
        if bb_set_path:
            self.stable_bbset_path.symlink_to(bb_set_path)
        if mmio_set_path:
            self.stable_mmioset_path.symlink_to(mmio_set_path)
        if bb_hash_path:
            self.stable_bbhash_path.symlink_to(bb_hash_path)

    def gen_trace(self, input_path, bb_set_path=None, mmio_set_path=None, bb_hash_path=None):
        # First set up symlinks to the input file and the trace destinations
        self.setup_links(input_path, bb_set_path, mmio_set_path, bb_hash_path)

        # And now, kick off child by sending go via control fd
        assert os.write(self.ctrl_write_fd, b"\0\0\0\0") == 4

        # Read two times from FD (one time for start, one time for emu finish)
        for _ in range(2):
            sock_read_len = len(os.read(self.status_read_fd, 4))
            if sock_read_len != 4:
                break

        # We have been successful in case the expected amount of bytes are read
        return sock_read_len == 4

class TraceGenWorker(rq.Worker): #pylint: disable=too-many-instance-attributes
    last_config_path = None

    trace_proc: TraceGenProc = None

    def __del__(self):
        if self.trace_proc:
            self.trace_proc.destroy()
        try:
            super().__del__()
        except AttributeError:
            pass

    def discard_trace_proc(self):
        if self.trace_proc:
            self.trace_proc.destroy()
            self.trace_proc = None

    def execute_job(self, job, queue): #pylint: disable=inconsistent-return-statements
        # self.set_state(WorkerStatus.BUSY)
        kwargs = job.kwargs

        bbl_set_path, mmio_set_path = kwargs.get(ARGNAME_BBL_SET_PATH, False), kwargs.get(ARGNAME_MMIO_SET_PATH)

        # If we don't have exactly bbl and MMIO set generation, forward to original implementation
        if (not bbl_set_path) or (not mmio_set_path) or \
            any(kwargs.get(argname) for argname in FORKSERVER_UNSUPPORTED_TRACE_ARGS):
            return super().execute_job(job, queue)

        self.prepare_job_execution(job)
        job.started_at = datetime.datetime.utcnow()

        config_path, input_path = job.args
        extra_args = kwargs.get(ARGNAME_EXTRA_ARGS, [])

        # If we need to switch to another config, kill current emulator child process
        if config_path != self.last_config_path:
            logger.info(f"Discarding current trace process due to changed config path. Config changed from {self.last_config_path} to {config_path}")
            self.discard_trace_proc()
            self.last_config_path = config_path

        # If we do not have a child process already, create one now
        if self.trace_proc is None:
            logger.info(f"Creating new trace process for config path {config_path}")
            # Start child process
            self.trace_proc = TraceGenProc(config_path, extra_args, gen_bb_set=True, gen_mmio_set=True)

        success = self.trace_proc.gen_trace(input_path, bbl_set_path, mmio_set_path)
        job.ended_at = datetime.datetime.utcnow()
        logger.info(f"Generated traces for {os.path.basename(input_path)} in {(job.ended_at-job.started_at).microseconds} us")
        if success:
            # Job success
            job.set_status(rq.job.JobStatus.FINISHED)

            self.handle_job_success(job=job, queue=queue,
                started_job_registry=queue.started_job_registry)
        else:
            # Job fail
            self.handle_job_failure(job=job, queue=queue,
                started_job_registry=queue.started_job_registry)

            # The emulator is likely in a bad state now, kill child
            logger.warning(f"[Trace Gen Job] got a failed tracing job (which ran from {job.started_at} to {job.ended_at}). closing file pipe FDs for kill + respawn.")
            self.trace_proc.destroy()
            self.trace_proc = None

        self.set_state(WorkerStatus.IDLE)
