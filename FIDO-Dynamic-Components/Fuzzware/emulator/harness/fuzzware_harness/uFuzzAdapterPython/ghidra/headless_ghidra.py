# usage: ghidra client, headless_ghidra.py is used to run ghidra headless
# Adapted from semu_fuzz for fuzzware-uFuzzAdapter.

import os, subprocess, threading, json, socket, logging
from time import time, sleep

DEBUG_LOG = "/tmp/ghidra_fuzzware.log"

logger = logging.getLogger("ghidra")
logger.setLevel(logging.DEBUG)
_fh = logging.FileHandler(DEBUG_LOG, mode='a')
_fh.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] %(message)s'))
logger.addHandler(_fh)
logger.propagate = False  # don't duplicate to root logger

GHIDRA_ANALYZE_HEADLESS = os.path.join(
    os.path.expanduser("~"), "ghidra", "support", "analyzeHeadless"
)


def _client_send_message(message, port, timeout=120):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', port)
    logger.debug("Trying to connect to Ghidra on port %d (timeout=%ds)...", port, timeout)
    waited = 0
    while waited < timeout:
        try:
            if client_socket.connect_ex(server_address) == 0:
                logger.debug("Ghidra connection successful after %ds", waited)
                break
        except socket.error as e:
            logger.debug("Socket error: %s", e)
        sleep(1)
        waited += 1
    else:
        logger.error("Ghidra not reachable on port %d after %ds, giving up", port, timeout)
        client_socket.close()
        return None
    try:
        logger.debug("Sending: %s", message)
        client_socket.sendall(message.encode())
        client_socket.settimeout(300)
        response = client_socket.recv(65536).decode()
        if response:
            logger.debug("Received %d bytes", len(response))
            return json.loads(response)
    except socket.error as e:
        logger.error("Communicate Error: %s", e)
    finally:
        client_socket.close()
    return None


def _delete_ghidra_project_lock_file(project_path):
    for root, dirs, files in os.walk(project_path):
        for f in files:
            if ".lock" in f:
                p = os.path.join(root, f)
                os.remove(p)
                logger.debug("Removed lock file: %s", p)


def _ghidra_thread(elf_path, port, project_path, project_name, script_path):
    """Daemon thread: launch Ghidra, capture output to log."""
    cmd = [
        GHIDRA_ANALYZE_HEADLESS,
        project_path,
        project_name,
        "-import", elf_path,
        "-overwrite",
        "-postScript", script_path,
        str(port),
    ]
    cmd_str = " ".join(map(str, cmd))
    logger.info("Launching Ghidra: %s", cmd_str)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,  # merge stderr→stdout
            encoding='utf-8',
            errors='replace',
        )
        # Read output line-by-line instead of blocking on communicate()
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                logger.info("GHIDRA: %s", line)
        proc.wait()
        logger.info("Ghidra exited with code %d", proc.returncode)
    except Exception as e:
        logger.error("Ghidra process failed: %s", e)


def start_ghidra(elf_path, config_dir):
    """Launch Ghidra headless analysis server for `elf_path`.
    Uses a port file to share a single Ghidra instance across workers.
    Returns the TCP port number, or 0 on failure."""
    if not os.path.exists(GHIDRA_ANALYZE_HEADLESS):
        logger.error("analyzeHeadless not found at %s", GHIDRA_ANALYZE_HEADLESS)
        return 0

    if not os.path.exists(elf_path):
        logger.error("ELF not found: %s", elf_path)
        return 0

    project_path = os.path.abspath(os.path.join(config_dir, 'ghidra_project'))
    port_file = os.path.join(project_path, 'ghidra_port.txt')
    os.makedirs(project_path, exist_ok=True)

    # Truncate log on first run of each pipeline session
    first_run = not os.path.exists(port_file)
    if first_run:
        try:
            with open(DEBUG_LOG, 'w') as _f: pass
        except Exception:
            pass

    # Check if another worker already launched (or is launching) Ghidra
    if os.path.exists(port_file):
        try:
            with open(port_file, 'r') as f:
                existing_port = int(f.read().strip())
            # Wait for the existing port to become ready (up to 120s)
            waited = 0
            while waited < 120:
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                        s.settimeout(2)
                        if s.connect_ex(('localhost', existing_port)) == 0:
                            logger.info("Reusing existing Ghidra on port %d (waited %ds)", existing_port, waited)
                            return existing_port
                except Exception:
                    pass
                sleep(1)
                waited += 1
            logger.error("Port %d from port_file never became ready after %ds", existing_port, waited)
            return 0
        except Exception:
            pass
        logger.info("Port file unreadable, starting new Ghidra")

    # Allocate a free port
    port = 0
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            port = s.getsockname()[1]
    except Exception:
        logger.error("Failed to allocate port")
        return 0

    logger.info("=== Ghidra startup: elf=%s port=%d project=%s ===",
                elf_path, port, project_path)

    file_name = os.path.basename(elf_path)
    project_name = file_name[:-4] if file_name.endswith(".elf") else file_name
    _delete_ghidra_project_lock_file(project_path)

    script_path = os.path.join(os.path.dirname(__file__), 'run_ghidra.py')
    if not os.path.exists(script_path):
        logger.error("run_ghidra.py not found at %s", script_path)
        return 0

    # Start Ghidra in daemon thread, capture output
    t = threading.Thread(
        target=_ghidra_thread,
        args=(elf_path, port, project_path, project_name, script_path),
        daemon=True,
    )
    t.start()

    # Write port file immediately (other workers will reuse)
    try:
        with open(port_file, 'w') as f:
            f.write(str(port))
    except Exception:
        pass

    logger.info("Ghidra launching asynchronously on port %d (TCP will be ready later)", port)
    return port


def ghidra_run_script(port, script_type, args=[]):
    """Send a command to the running Ghidra server and return the result."""
    starttime = time()
    logger.info("Ghidra run_script: type=%s args=%s", script_type, args)
    message = json.dumps([script_type] + [str(a) for a in args])
    response = _client_send_message(message, port)

    if response is None:
        logger.error("Ghidra run_script: no response (Ghidra not running?)")
        raise RuntimeError(f"Ghidra not responding on port {port}")

    if script_type == "global_static_data":
        if not isinstance(response, list):
            logger.error("Ghidra response not a list: %s", response)
            raise RuntimeError(f"Ghidra response not a list! {response}")
        if len(response) == 1 and not isinstance(response[0], (list, dict)):
            logger.info("Effective read point: %s", response[0])
            return response[0], []

        dt_dict_list = response[:-1]
        global_vars = response[-1]
        elapsed = time() - starttime
        logger.info("Ghidra global_static_data done in %.1fs: dt=%s vars=%d items",
                    elapsed, dt_dict_list, len(global_vars) if isinstance(global_vars, list) else 0)
        return dt_dict_list, global_vars

    elif script_type == "callind_collect":
        logger.info("Ghidra callind_collect: %d items", len(response) if isinstance(response, list) else 0)
        return response
    elif script_type == "correct_lr":
        logger.info("Ghidra correct_lr: %s → 0x%x", args[0] if args else '?', response)
        return int(response, 16)
    elif script_type == "get_ancestor":
        logger.info("Ghidra get_ancestor: %s", response)
        if response == [None]:
            return [None]
        return [int(x, 16) for x in response]

    return response
