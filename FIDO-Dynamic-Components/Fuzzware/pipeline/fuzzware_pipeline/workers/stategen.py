from ..run_target import run_target
import subprocess

def gen_mmio_states_at(config_path, input_path, output_dir, pc_address_pairs, name_prefix=None, extra_args=None):
    if extra_args is None:
        extra_args = []

    if name_prefix is not None:
        extra_args += ["--dumped-mmio-name-prefix", name_prefix]

    extra_args += ["--state-out", output_dir]

    extra_args += ["--dump-mmio-states"]
    extra_args += ["--dumped-mmio-contexts", ",".join(["{:x}:{:x}".format(pc, address) for pc, address in pc_address_pairs])]

    run_target(config_path, input_path, extra_args, stdout=subprocess.DEVNULL, silent=True)
    return True
