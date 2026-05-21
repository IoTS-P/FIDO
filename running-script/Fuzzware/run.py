#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Start multiple fuzzware pipeline instances in parallel in background (only through binary executable, no longer supports workon).
Example:
  python3 run.py --groups 5 --fuzzware-path ~/.virtualenvs/fuzzware/bin/fuzzware
"""
import os
import sys
import time
import argparse
import shlex
import subprocess

DEFAULT_GROUPS = 5
DEFAULT_PROJECT_PREFIX = "1107_adapter_"
DEFAULT_FUZZWARE_PATH = os.path.expanduser("~/.virtualenvs/fuzzware_ufuzzadapter/bin/fuzzware")
# DEFAULT_FUZZWARE_PATH = os.path.expanduser("~/.virtualenvs/fuzzware/bin/fuzzware")
LOG_BASE_DIR = os.path.join(os.getcwd(), "fuzzware_runs")

# ...existing code...
def start_instance(project_name, fuzzware_path, run_for="24:00:00"):
    os.makedirs(LOG_BASE_DIR, exist_ok=True)
    log_dir = os.path.join(LOG_BASE_DIR, project_name)
    os.makedirs(log_dir, exist_ok=True)
    stdout_path = os.path.join(log_dir, f"{project_name}_stdout.log")
    stderr_path = os.path.join(log_dir, f"{project_name}_stderr.log")

    fuzzware_path_expanded = os.path.expanduser(fuzzware_path)
    if not os.path.isfile(fuzzware_path_expanded):
        raise FileNotFoundError(f"fuzzware executable not found: {fuzzware_path_expanded}")

    cmd_list = [fuzzware_path_expanded, "pipeline", "--aflpp", "--run-for", run_for, "-p", project_name]
    proc = subprocess.Popen(cmd_list, stdout=open(stdout_path, "ab"),
                            stderr=open(stderr_path, "ab"), cwd=os.getcwd(),
                            start_new_session=True)
    return proc.pid

# ...existing code...
def main():
    p = argparse.ArgumentParser(description="Start multiple fuzzware pipeline instances in parallel in background (only through binary)")
    p.add_argument("--groups", "-g", type=int, default=DEFAULT_GROUPS, help="Number of instances to start (default 5)")
    p.add_argument("--project-prefix", "-P", default=DEFAULT_PROJECT_PREFIX, help="Project name prefix")
    p.add_argument("--fuzzware-path", default=DEFAULT_FUZZWARE_PATH, help="Full path to fuzzware executable (must exist)")
    p.add_argument("--run-for", default="24:00:00", help="Duration passed to --run-for")
    args = p.parse_args()

    fuzzware_path = os.path.expanduser(args.fuzzware_path)
    if not os.path.isfile(fuzzware_path):
        print(f"Error: Specified fuzzware executable does not exist: {fuzzware_path}", file=sys.stderr)
        sys.exit(2)

    pids = []
    for i in range(1, args.groups + 1):
        project = f"{args.project_prefix}{i}"
        try:
            pid = start_instance(project, fuzzware_path=fuzzware_path, run_for=args.run_for)
            print(f"Started: {project} -> PID {pid}")
            pids.append((project, pid))
        except Exception as e:
            print(f"Failed to start: {project} -> {e}", file=sys.stderr)
        time.sleep(0.4)  # Small delay to avoid launching too many processes at once

    print("\nStartup complete. Log directory:", LOG_BASE_DIR)
    for project, pid in pids:
        print(f"  {project}  PID={pid}")

if __name__ == "__main__":
    main()
# ...existing code...