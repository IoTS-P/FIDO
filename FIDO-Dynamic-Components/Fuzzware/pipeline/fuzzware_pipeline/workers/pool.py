import os
import random
import subprocess
import time
from math import ceil

import redis
import rq
from fuzzware_pipeline.logging_handler import logging_handler

from ..const import (RQ_JOB_FAILURE_TTL, RQ_JOB_TTL, RQ_MODELING_JOB_TIMEOUT,
                     RQ_RESULT_TTL, RQ_STATEGEN_JOB_TIMEOUT)
from ..naming_conventions import (REDIS_QUEUE_NAME_MODELING,
                                  REDIS_QUEUE_NAME_STATE_GEN_JOBS,
                                  REDIS_QUEUE_NAME_TRACE_GEN_JOBS,
                                  RQ_DUMP_FILE, SESS_FILENAME_CONFIG,
                                  class_path, find_modeling_venv,
                                  get_input_path_components,
                                  mmio_state_name_prefix_for_input_path,
                                  trace_paths_for_input)
from .. import naming_conventions as nc
from ..util.eval_utils import add_job_timing_entries
from ..workers import stategen, tracegen

logger = logging_handler().get_logger("pipeline")

WORKER_SHUTDOWN_TIMEOUT = 0.25
REDIS_SERVER_TIMEOUT = 5
REDIS_PORT_RANGE_START = 2048
REDIS_PORT_RANGE_END = 60000
REDIS_PORT_RETRIES = 100
MMIO_MODELING_INCLUDE_PATH = "fuzzware_modeling.analyze_mmio.analyze_mmio_and_store"

class WorkerPool:
    parent: None # : Pipeline
    conn: redis.Redis
    redis_port: int
    db_proc: subprocess.Popen
    procs: dict # {}
    jobs: list
    write_logs: bool

    job_queue_trace_gen: rq.Queue
    job_queue_state_gen: rq.Queue
    job_queue_modeling: rq.Queue

    def __init__(self, parent, write_logs):
        self.worker_procs = {
            REDIS_QUEUE_NAME_TRACE_GEN_JOBS: [],
            REDIS_QUEUE_NAME_MODELING: []
        }
        self.parent = parent
        self.jobs = []
        self.db_proc = None
        self.write_logs = write_logs

        self.start_redis()

        # After starting our own redis instance, make sure it is up
        redis_up = False
        for _ in range(5):
            if self.db_up():
                redis_up = True
                break
            time.sleep(0.1)

        if not redis_up:
            print(f"Got answer from redis-server ping: {redis_up}")
            raise(Exception("Redis server not up?"))

        self.job_queue_trace_gen = rq.Queue(REDIS_QUEUE_NAME_TRACE_GEN_JOBS, connection=self.conn)
        self.job_queue_state_gen = rq.Queue(REDIS_QUEUE_NAME_STATE_GEN_JOBS, connection=self.conn)
        self.job_queue_modeling = rq.Queue(REDIS_QUEUE_NAME_MODELING, connection=self.conn)

        self.spawn_workers(self.parent.num_main_fuzzer_procs)
        time.sleep(1)
        self.check_running_procs()


    def check_running_procs(self):
        for queue_name, procs in self.worker_procs.items():
            for proc in procs:
                if proc.poll() is not None:
                    raise Exception("'{}' worker spawned by WorkerPool is not running anymore".format(queue_name))

        if self.db_proc and self.db_proc.poll() is not None:
            raise Exception("database process spawned by WorkerPool is not running anymore")

    def db_up(self):
        try:
            res = self.conn.ping()
            if not res:
                self.conn.close()
                self.conn = redis.Redis(port=self.redis_port)
                logger.warning("Redis server up, but ping still errored.")
                return self.conn.ping()
            else:
                logger.warning(f"Redis ping returned: {res}")
            return res
        except redis.exceptions.ConnectionError:
            logger.info("Could not establish connection with redis (yet)")
            return False

    def worker_log_path(self, queue_name):
        return self.parent.get_logfile_path("worker_{}_{:02d}".format(queue_name, len(self.worker_procs[queue_name])))

    def spawn_gen_worker(self):
        if self.write_logs:
            logger.info("[WorkerPool] enabling logging for gen worker!")
            stdout_path = open(self.worker_log_path(REDIS_QUEUE_NAME_TRACE_GEN_JOBS), "w")
        else:
            stdout_path = subprocess.DEVNULL

        self.worker_procs[REDIS_QUEUE_NAME_TRACE_GEN_JOBS].append(subprocess.Popen(["python3", "-m", "rq.cli", "worker", "--url", f"redis://localhost:{self.redis_port}", "-q", "-w",  class_path(tracegen.TraceGenWorker), REDIS_QUEUE_NAME_STATE_GEN_JOBS, REDIS_QUEUE_NAME_TRACE_GEN_JOBS], stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT)) #pylint: disable=consider-using-with

    def spawn_modeling_worker(self, burst=False):
        modeling_venv_path = find_modeling_venv()

        venv_python_path = os.path.join(modeling_venv_path, "bin", "python3")
        if not os.path.exists(venv_python_path):
            raise Exception("python inside venv could not be found in modeling venv")

        if self.write_logs:
            logger.info("[WorkerPool] enabling logging for modeling worker!")
            stdout_path = open(self.worker_log_path(REDIS_QUEUE_NAME_MODELING) + ("_burst" if burst else ""), "w")
        else:
            logger.info("[WorkerPool] suppressing logging for modeling worker")
            stdout_path = subprocess.DEVNULL

        popen_args = [venv_python_path, "-m", "fuzzware_modeling.rq_worker", "--port", f"{self.redis_port:d}"]
        if burst:
            popen_args += ["--burst"]
        popen_args += [ REDIS_QUEUE_NAME_MODELING ]

        worker_proc = subprocess.Popen(popen_args, stdout=stdout_path, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT) #pylint: disable=consider-using-with

        if not burst:
            self.worker_procs[REDIS_QUEUE_NAME_MODELING].append(worker_proc)

    def start_redis(self):
        logger.info("[WorkerPool] Starting redis server")

        for i in range(1, REDIS_PORT_RETRIES+1):
            self.redis_port = random.randint(REDIS_PORT_RANGE_START, REDIS_PORT_RANGE_END)
            self.db_proc = subprocess.Popen(['redis-server', '--save', '', '--port', f'{self.redis_port:d}', '--logfile', os.path.join(self.parent.base_dir, nc.PIPELINE_DIRNAME_LOGS, 'redis.log') ], stdout=subprocess.DEVNULL, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT) #pylint: disable=consider-using-with

            time.sleep(0.25)
            self.conn = redis.Redis(port=self.redis_port)
            if self.db_proc.poll() is not None:
                logger.warning(f"[Redis server starting try {i} / {REDIS_PORT_RETRIES}] Trying to start redis on port {self.redis_port} failed immediately. Retrying...")
                continue

            for _ in range(REDIS_SERVER_TIMEOUT):
                if self.db_up():
                    logger.info(f"Redis server successfully started on port {self.redis_port:d}")
                    return

                logger.info("Waiting for redis server to come up...")
                time.sleep(1)

            logger.warning(f"[Redis server starting try {i} / {REDIS_PORT_RETRIES}] Trying to start redis on port {self.redis_port} did not come up even after waiting. Retrying...")
            self.db_proc.kill()
            self.db_proc = None

        # If we were unable to start redis, give up
        raise Exception("Redis server did not come up")

    def spawn_workers(self, num_fuzzer_procs):
        num_running_modeling_workers = len(rq.Worker.all(queue=self.job_queue_modeling))
        num_req_modeling_workers = max(ceil(num_fuzzer_procs / 4), 1)
        if num_req_modeling_workers > num_running_modeling_workers:
            for _ in range(num_req_modeling_workers - num_running_modeling_workers):
                logger.info("[WorkerPool] Spawning additional modeling worker")
                self.spawn_modeling_worker()

        # All workers which listen to trace generation also listen to state generation, so we can count them from one of the queues
        num_running_gen_workers = len(rq.Worker.all(queue=self.job_queue_trace_gen))
        num_req_gen_workers = max(ceil(num_fuzzer_procs / 2), 1)
        if num_req_gen_workers > num_running_gen_workers:
            for _ in range(num_req_gen_workers - num_running_gen_workers):
                logger.info("[WorkerPool] Spawning additional gen worker")
                self.spawn_gen_worker()

    def shutdown(self, hard=False):
        logger.info("[WorkerPool] Killing workers")

        if hard:
            for queue_name, procs in self.worker_procs.items():
                # RIP workers
                for proc in procs:
                    proc.kill()

            if self.db_proc:
                self.db_proc.kill()
                self.db_proc = None
        else:
            for queue_name, procs in self.worker_procs.items():
                # Give workers a graceful exit opportunity
                for proc in procs:
                    proc.terminate()

            for queue_name, procs in self.worker_procs.items():
                while procs:
                    proc = procs.pop()
                    if proc.poll() is None:
                        logger.info(f"Waiting for '{queue_name}' worker proc")
                        time.sleep(WORKER_SHUTDOWN_TIMEOUT)
                        proc.kill()

            if self.db_proc:
                self.db_proc.terminate()

    def enqueue_job_trace_gen(self, input_path):
        input_path = os.path.abspath(input_path)

        _, session_name, _, _, _ = get_input_path_components(input_path)
        bbl_trace_path, ram_trace_path, mmio_trace_path, bbl_set_path, mmio_set_path, _ = trace_paths_for_input(input_path)
        if not self.parent.do_full_tracing:
            bbl_trace_path, ram_trace_path, mmio_trace_path = None, None, None

        config_path = os.path.join(self.parent.base_dir, session_name, SESS_FILENAME_CONFIG)
        self.jobs.append(self.job_queue_trace_gen.enqueue(tracegen.gen_traces, config_path, input_path,
            bbl_trace_path=bbl_trace_path,
            ram_trace_path=ram_trace_path,
            mmio_trace_path=mmio_trace_path,
            bbl_set_path=bbl_set_path,
            mmio_set_path=mmio_set_path,
            extra_args=self.parent.curr_main_session.extra_runtime_args,
            result_ttl=RQ_RESULT_TTL, ttl=RQ_JOB_TTL, failure_ttl=RQ_JOB_FAILURE_TTL
        ))

    def enqueue_job_gen_mmio_states(self, input_path, pc_mmio_address_pairs):
        input_path = os.path.abspath(input_path)

        _, session_name, _, _, _ = get_input_path_components(input_path)
        config_path = os.path.join(self.parent.base_dir, session_name, SESS_FILENAME_CONFIG)
        state_name_prefix = mmio_state_name_prefix_for_input_path(input_path)

        self.jobs.append(self.job_queue_state_gen.enqueue(stategen.gen_mmio_states_at, config_path, input_path,
            self.parent.mmio_states_dir,
            pc_mmio_address_pairs,
            name_prefix=state_name_prefix,
            extra_args=self.parent.curr_main_session.extra_runtime_args,
            result_ttl=RQ_RESULT_TTL, ttl=RQ_JOB_TTL, failure_ttl=RQ_JOB_FAILURE_TTL, job_timeout=RQ_STATEGEN_JOB_TIMEOUT
        ))

    def enqueue_job_analyze_model(self, input_filename, mmio_state_path):
        mmio_state_path = os.path.abspath(mmio_state_path)

        outdir = self.parent.config_snippets_dir
        out_path = os.path.join(outdir, input_filename)
        self.jobs.append(self.job_queue_modeling.enqueue(
            MMIO_MODELING_INCLUDE_PATH, [mmio_state_path], out_path, self.parent.default_config_map,
            # Give the modeling timeout mechanism time to react to an impending timeout
            RQ_MODELING_JOB_TIMEOUT - 30,
            result_ttl=RQ_RESULT_TTL, ttl=RQ_JOB_TTL, failure_ttl=RQ_JOB_FAILURE_TTL, job_timeout=RQ_MODELING_JOB_TIMEOUT
        ))

    def clean_lost_jobs(self):
        to_delete = []
        for job in self.jobs:
            try:
                job.refresh()
            except rq.exceptions.NoSuchJobError:
                self.parent.add_warning_line("Cleaning up no longer existing job: {} [args: {}]".format(job, job.args))
                to_delete.append(job)

        for job in to_delete:
            self.jobs.remove(job)

    def collect_job_timings(self, max_jobs=-1):
        # do this at most every second or if we looped for quite a bit so we don't lose jobs
        new_job_timing_entries = []
        num_queried = 0
        for job in self.jobs:
            num_queried += 1
            job_status = job.get_status()
            if job_status in ('finished', 'failed'):
                # Get timing data from db
                try:
                    job.refresh()
                except rq.exceptions.NoSuchJobError:
                    pass

                if job_status == 'failed':
                    self.parent.add_warning_line("job failed: {}, started at: {}, args: {}, exc_info: {}".format(job.func_name, job.started_at, job.args, job.exc_info))
                self.jobs.remove(job)
                new_job_timing_entries.append((job.func_name, job_status, job.enqueued_at, job.started_at, job.ended_at))

            if max_jobs != -1 and num_queried > max_jobs:
                # If we are busy, don't spend too much time housekeeping
                break

        if new_job_timing_entries:
            add_job_timing_entries(self.parent.job_timings_file, new_job_timing_entries)
            self.parent.job_timings_file.flush()

    def check_lost_jobs(self):
        for i in range(min(len(self.jobs), 10)):
            try:
                job = self.jobs[i]
                job.refresh()
                logger.info("remaining job ({}, status: {}): {}".format(job.func_name, job.get_status(), repr(job)))
            except rq.exceptions.NoSuchJobError:
                logger.error("job no longer exists: {} [args: {}]".format(job.func_name, job.args))
                self.clean_lost_jobs()
                break
