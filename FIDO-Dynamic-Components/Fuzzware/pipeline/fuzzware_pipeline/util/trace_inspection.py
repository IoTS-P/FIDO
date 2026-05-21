from fuzzware_harness.tracing.serialization import (parse_bbl_set,
                                                    parse_bbl_trace,
                                                    parse_mmio_set,
                                                    parse_mmio_trace)


def bbl_trace_contains(trace_file_path, bbl_addr):
    for _, pc, _ in parse_bbl_trace(trace_file_path):
        if pc == bbl_addr:
            return True
    return False

def bbl_set_contains(set_file_path, bbl_addr):
    for pc in parse_bbl_set(set_file_path):
        if pc == bbl_addr:
            return True
    return False

def mmio_trace_contains_one_context(trace_file_path, mmio_contexts):
    for _, pc, _, _, _, _, _, address, _ in parse_mmio_trace(trace_file_path):
        if (pc, address) in mmio_contexts:
            return True
    return False

def mmio_set_contains_one_context(set_file_path, mmio_contexts):
    for pc, address, _ in parse_mmio_set(set_file_path):
        if (pc, address) in mmio_contexts:
            return True
    return False
