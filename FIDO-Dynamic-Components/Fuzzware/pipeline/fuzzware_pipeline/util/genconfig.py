import os
import pathlib
import string
import subprocess

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from fuzzware_harness.util import bytes2int
from fuzzware_pipeline.logging_handler import logging_handler

logger = logging_handler().get_logger("pipeline")

PRINTABLE_ASCIIVALS = frozenset(map(ord, string.printable))

OBJCOPY_UTIL = "arm-none-eabi-objcopy"
DYNAMICALLY_ADDED_REGION_NAME_PREFIX = "dynamically_added_crash_region_"

# From cortexm_memory.yml
DEFAULT_MEM_MAP = {
  "ram":  {"base_addr":  0x20000000, "size": 0x00100000, "permissions": "rw-"},
  "mmio": {"base_addr":  0x40000000, "size": 0x20000000, "permissions": "rw-"},
  "nvic": {"base_addr":  0xe0000000, "size": 0x10000000, "permissions": "rw-"},
  "irq_ret": {"base_addr": 0xfffff000, "size": 0x1000, "permissions": "--x"}
}
# Some padded size after raw ROM contents
DEFAULT_ADD_TEXT_SIZE = 0x10000

ELF_MAGIC = b"\x7f\x45\x4c\x46"
def is_elf(path):
    with open(path, "rb") as f:
        magic = f.read(len(ELF_MAGIC))
    from binascii import hexlify
    logger.info(f"looking at file contents: {hexlify(magic)} == {hexlify(ELF_MAGIC)}")
    return magic == ELF_MAGIC

def extract_elf(in_path, out_path):
    assert is_elf(in_path)

    subprocess.check_call([OBJCOPY_UTIL, "-O", "binary", in_path, out_path])



def collect_pointers(binary_contents):
    pointers = []

    initial_sp, reset_vector_addr = bytes2int(binary_contents[:4]), bytes2int(binary_contents[4:8])
    logger.info(f"Got reset vector: 0x{reset_vector_addr:08x}")
    min_rom_ptr, max_rom_ptr = reset_vector_addr, reset_vector_addr

    def is_rom_ptr(addr, curr_min, curr_max):
        if addr < 8:
            return False

        # Check range
        outer_edge_size = len(binary_contents)-(curr_max - curr_min)

        return curr_min-outer_edge_size <= addr <= curr_max + outer_edge_size

    for i in range(8, len(binary_contents), 4):
        val = bytes2int(binary_contents[i:i+4])

        if is_rom_ptr(val, min_rom_ptr, max_rom_ptr):
            if val < min_rom_ptr:
                min_rom_ptr = val
            elif val > max_rom_ptr:
                max_rom_ptr = val
            pointers.append(val)

    return initial_sp, reset_vector_addr, pointers

def has_ascii_at_offset(binary_contents, offset, min_len=8):
    if len(binary_contents) < offset + min_len:
        return False
    res = all(map(lambda ind: binary_contents[offset+ind] in PRINTABLE_ASCIIVALS, range(min_len)))
    return res

THUMB_OPC_PUSH = 0xB5
THUMB_OPC_STMFD1 = 0x2D
THUMB_OPC_STMFD2 = 0xE9
THUMB_OPC_INFLOOP = 0xE7FE
FN_PROLOGUE_OPCODES = (THUMB_OPC_PUSH, THUMB_OPC_STMFD1, THUMB_OPC_STMFD2)
def has_fn_prologue_at_offset(binary_contents, binary_offset):
    if binary_offset & 1 != 1:
        return False
    if len(binary_contents) <= binary_offset:
        return False
    # Remove thumb bit
    binary_offset &= ~1

    res = binary_contents[binary_offset+1] in FN_PROLOGUE_OPCODES
    if not res:
        res = THUMB_OPC_INFLOOP == bytes2int(binary_contents[binary_offset:binary_offset+2])

    if res:
        logger.info(f"Found function prologue at offset {binary_offset:x}")

    return res

def can_be_good_offset(binary_contents, ptr, base_offset):
    binary_offset = ptr - base_offset
    if binary_offset < 0 or binary_offset > len(binary_contents):
        return False

    # We are pointing inside the image, let's see now
    # 1. Is string?
    if has_ascii_at_offset(binary_contents, binary_offset):
        logger.info(f"Found ascii! (ptr 0x{ptr:08x}, offset: {base_offset:x}")
        return True

    # 2. Is function pointer?
    if has_fn_prologue_at_offset(binary_contents, binary_offset):
        return True

    return False

PAGE_SIZE = 0x1000
PAGE_MASK = PAGE_SIZE - 1
def find_text_mapping(binary_path):
    # Find by raw binary
    # We do this via FirmXRay's algorithm:
    # 1. scan for pointer values
    # 2. Guess values based on found pointers and check whether pointers point to functions/strings
    # 3. Choose base address with most matches
    with open(binary_path, "rb") as f:
        binary_contents = f.read()
    aligned_contents_len = len(binary_contents)
    if aligned_contents_len & PAGE_MASK:
        aligned_contents_len = (aligned_contents_len & (~PAGE_MASK)) + PAGE_SIZE

    initial_sp, reset_vector, pointers = collect_pointers(binary_contents)
    pointers = sorted(set(pointers))

    min_ptr, max_ptr = pointers[0], pointers[-1]
    _, _, aligned_reset_vector = min_ptr & (~PAGE_MASK), max_ptr & (~PAGE_MASK), reset_vector & (~PAGE_MASK)
    first_offset_candidate = -aligned_contents_len # -min(aligned_contents_len, aligned_min_ptr)
    #print("first oc {:x}".format(first_offset_candidate))
    #print("reset_vector {:x}".format(reset_vector))
    if (reset_vector - first_offset_candidate) < 0: #sanity check, necessary for certain boards
        first_offset_candidate = 0
    #print("first oc {:x}".format(first_offset_candidate))

    last_offset_candidate = aligned_contents_len

    matches_per_offset = {}
    for offset_candidate in range(first_offset_candidate, last_offset_candidate, PAGE_SIZE):
        logger.info(f"Checking offset candidate: {offset_candidate}")
        matches_per_offset[offset_candidate] = sum(map(lambda ptr: can_be_good_offset(binary_contents, ptr-aligned_reset_vector, offset_candidate), pointers))

    best_candidates = sorted(matches_per_offset.items(), key=lambda entry: matches_per_offset[entry[0]])
    best_candidate_offset = best_candidates[-1][0]
    base_addr = aligned_reset_vector + best_candidate_offset
    logger.info(f"Got base address: 0x{base_addr:08x} with {matches_per_offset[best_candidate_offset]} plausible address matches (second best: {best_candidates[-2][1]}).")

    return initial_sp, base_addr, os.stat(binary_path).st_size + DEFAULT_ADD_TEXT_SIZE

def merge_adjacent_regions(memregion_config):
    """
    Merge scattered memory regions into consecutive regions
    """
    region_ends = {
        entry["base_addr"]+entry["size"]: region_name for region_name, entry in memregion_config.items()
    }

    removed_region_names = []
    for region_name in memregion_config:
        start, size = memregion_config[region_name]['base_addr'], memregion_config[region_name]['size']
        # Is our region the start of another region?
        if start in region_ends:
            adjacent_region_name = region_ends.pop(start)
            memregion_config[adjacent_region_name]["size"] += size

            region_ends[start+size] = adjacent_region_name

            # Remove now merged_in fragment
            memregion_config[region_name] = None
            removed_region_names.append(region_name)

    for rname in removed_region_names:
        del memregion_config[rname]

def add_missing_regions(existing_mem_config, add_entries):
    for rname, entry in add_entries.items():
        start = entry['base_addr']
        end = start + entry['size']
        should_add = True

        logger.info(f"Looking at region to add: {rname} ({start:x}-{end:x})")

        consumed_region_names = set()
        sorted_other_regions = sorted(existing_mem_config, key=lambda k: existing_mem_config[k]['base_addr'])
        for i, other_rname in enumerate(sorted_other_regions):
            if other_rname in consumed_region_names:
                continue
            other_entry = existing_mem_config[other_rname]
            other_start = other_entry['base_addr']
            other_end = other_start + other_entry['size']
            print(f"comparing to {other_rname} ({other_start:x}-{other_end:x})")

            # Need to extend next region backwards?
            if start < other_start <= end:
                logger.info(f"Setting start of region {other_rname} ({other_start:x}-{other_end:x}) to {start:x}")
                prepend_size = other_start - start
                other_start = start
                other_entry['base_addr'] = other_start
                other_entry['size'] += prepend_size

            # Do we also need to extend other region forward?
            if other_start <= start <= other_end < end:
                # If we need to extend the other region forward, make sure not to clash with the region following that
                if i+1 < len(sorted_other_regions):
                    next_region_name = sorted_other_regions[i+1]
                    next_start = existing_mem_config[next_region_name]['base_addr']
                    if end > next_start:
                        # We got a collision. Is it dynamically added?
                        if DYNAMICALLY_ADDED_REGION_NAME_PREFIX in next_region_name:
                            logger.warning(f"While extending forward, collided with dynamically added region {next_region_name}, consuming it")
                            consumed_region_names.add(next_region_name)
                            next_end = next_start + existing_mem_config[next_region_name]['size']

                            end = max(end, next_end)
                            del existing_mem_config[next_region_name]
                        else:
                            logger.warning("While extending forward, collided with next region, setting end to other region's start")
                            end = next_start

                append_size = end - other_end
                other_end = end
                logger.info(f"Extending end of region {other_rname} ({other_start:x}-{other_start+other_entry['size']:x}) to {other_end:x}")
                other_entry['size'] += append_size

            # Fully contained? Then we added it or it was already included
            if other_start <= start <= other_end and other_start <= end <= other_end:
                logger.info(f"Region {rname} ({start:x}-{end:x}) fully contained in region {other_rname}")
                should_add = False
                break

        # We did not find an overlap, so add the section
        if should_add:
            logger.info(f"Adding memory region {rname} ({start:#10x}-{end:#10x}) to config")
            while rname in existing_mem_config:
                rname = "_" + rname
            existing_mem_config[rname] = {**entry}

def align_mem_map_to_pages(mem_config):
    """
    Given an already non-colliding memory map, we make
    sure that two regions are not on the same page boundary.
    """
    sorted_region_names = sorted(mem_config, key=lambda reg_name: mem_config[reg_name]['base_addr'])

    region_indices_to_eliminate = []

    for i, region_name in enumerate(sorted_region_names):
        if i == len(sorted_region_names):
            break

        if i in region_indices_to_eliminate:
            continue

        cur_start = mem_config[region_name]['base_addr']
        cur_size = mem_config[region_name]['size']
        cur_end = cur_start + cur_size
        logger.info(f"[align_mem_map_to_pages] looking at region '{region_name}', base: {cur_start:#010x}, size: {cur_size:#x}")

        # If we are aligned, there is no need to shift anything
        if cur_end & PAGE_MASK == 0:
            continue

        next_start = mem_config[sorted_region_names[i+1]]['base_addr']
        if cur_end & ~PAGE_MASK == next_start & ~PAGE_MASK:
            logger.warning(f"Regions {region_name} and {sorted_region_names[i+1]} end/start on the same page, unaligned.")
            cur_size += PAGE_SIZE - (cur_end % PAGE_SIZE)
            next_shrink_size = PAGE_SIZE - (next_start % PAGE_SIZE)
            next_start += next_shrink_size

            logger.warning(f"Adjusting {region_name} size to {cur_size:08x}.")
            logger.warning(f"Adjusting {sorted_region_names[i+1]} start to {next_start:#010x}.")

            mem_config[sorted_region_names[i+1]]['base_addr'] = next_start
            if next_shrink_size <= mem_config[sorted_region_names[i+1]]['size']:
                mem_config[sorted_region_names[i+1]]['size'] -= next_shrink_size
            else:
                logger.warning(f"Fully removing region {sorted_region_names[i+1]} which spanned less than a page")
                region_indices_to_eliminate.append(i+1)

            mem_config[region_name]['size'] = cur_size

            # TODO: We might have different permissions here. But if they differed,
            # that would not have worked on most architectures anyways.
            # What we could do instead is create a single-page region with merged permissions

    for i in region_indices_to_eliminate:
        del mem_config[sorted_region_names[i]]

def collect_and_merge_elf_segments(elf_path):
    res = load_elf_segment_mem_regions(elf_path)

    merge_adjacent_regions(res)
    return res

def add_mem_map(config_basedir, config_map, binary_path, elf_path, ivt_offset):
    if "memory_map" not in config_map:
        config_map["memory_map"] = {}
    mem_cfg = config_map["memory_map"]

    # Fill from default memory map
    for memregion_name, memregion_config in DEFAULT_MEM_MAP.items():
        if memregion_name not in mem_cfg:
            mem_cfg[memregion_name] = memregion_config

    binary_already_mapped = False
    abs_binpath = os.path.abspath(binary_path)
    for region_config in mem_cfg.values():
        f = region_config.get("file")
        if f and f == abs_binpath:
            binary_already_mapped = True
            break

    if not binary_already_mapped:
        # We will register the binary image as "text", make sure it is not taken
        assert "text" not in mem_cfg

        _, text_base, text_size = find_text_mapping(binary_path)
        mem_cfg["text"] = {
            "base_addr": text_base,
            "size": text_size,
            "ivt_offset" : ivt_offset,
            # get the relative path
            "file": str(pathlib.Path(binary_path).relative_to(pathlib.Path(config_basedir))),
            "permissions": "r-x"
        }

    if elf_path:
        elf_memory_regions = collect_and_merge_elf_segments(elf_path)
        logger.info(f"collected ELF memory regions: {elf_memory_regions}")
        add_missing_regions(config_map['memory_map'], elf_memory_regions)
        align_mem_map_to_pages(config_map['memory_map'])

def gen_syms(elf_path):
    # Based on https://github.com/eliben/pyelftools/blob/master/scripts/readelf.py
    res = {}

    with open(elf_path, "rb") as f:
        elffile = ELFFile(f)
        symbol_tables = [(idx, s) for idx, s in enumerate(elffile.iter_sections())
                            if isinstance(s, SymbolTableSection)]

        if not symbol_tables and elffile.num_sections() == 0:
            logger.warning("No symbol sections...")
            return res

        for _, section in symbol_tables:
            if section['sh_entsize'] == 0:
                logger.warning("section['sh_entsize'] == 0")
                # Symbol table has no entries
                continue

            for _, symbol in enumerate(section.iter_symbols()):
                if symbol.name and "$" not in symbol.name:
                    res[symbol['st_value']] = symbol.name

    return res

def load_elf_segment_mem_regions(elf_path):
    # Based on https://github.com/eliben/pyelftools/blob/master/scripts/readelf.py

    res = {}
    with open(elf_path, "rb") as f:
        elffile = ELFFile(f)

        if elffile.num_sections() == 0:
            return res

        for section in elffile.iter_sections():
            if (section['sh_flags'] & SH_FLAGS.SHF_ALLOC) == 0:
                logger.debug(f"Section {section.name} does not have alloc flag set, skipping")
                continue
            if section['sh_size'] == 0:
                logger.debug(f"Section {section.name} has 0 size, skipping")
                continue
            res[section.name] = {
                'base_addr': section['sh_addr'],
                'size': section['sh_size'],
                'permissions': ('r'
                    + ("w" if section['sh_flags'] & SH_FLAGS.SHF_WRITE else "-")
                    + ("x" if section['sh_flags'] & SH_FLAGS.SHF_EXECINSTR else "-")
                )
            }

    return res


def gen_configs(config_basedir, config_map, binary_path, elf_path, ivt_offset=0, ti_flag=False):

    #check for proprietary header in binary file
    #check_for_header(binary_path)
    add_mem_map(config_basedir, config_map, binary_path, elf_path, ivt_offset)

    if elf_path and 'symbols' not in config_map:
        logger.info("Generating symbols")
        config_map['symbols'] = gen_syms(elf_path)

    if 'interrupt_triggers' not in config_map:
        config_map['interrupt_triggers'] = {
            "trigger": {
                "fuzz_mode": "round_robin",
                "every_nth_tick": 1000
            }
        }

    #necessary actions for some texas instruments samples
    if ti_flag:
        #add rom region
        config_map['memory_map']['ti_rom'] = {
                "base_addr": 0x10000000,
                "file": ti_flag,
                "size": 0x20000,
                "permissions": "r-x"
        }
        print(config_map)
        #change ram size to 0x400000
        config_map['memory_map']['ram']['size'] = 0x400000
        #add is_entry = True to text
        config_map['memory_map']['text']['is_entry'] = True

NUM_CRASH_MAPPED_AROUND_PAGES = 5
def add_region_for_crashing_addr(config_map, crash_addr):
    page_start = crash_addr & ~PAGE_MASK
    mapping_distance = NUM_CRASH_MAPPED_AROUND_PAGES * PAGE_SIZE
    new_region_entry = {
        f'{DYNAMICALLY_ADDED_REGION_NAME_PREFIX}{crash_addr:08x}': {
            'base_addr': max(page_start - mapping_distance, 0),
            'size': 2 * mapping_distance,
            'permissions': 'rw-'
        }
    }

    logger.info(f"Adding region for crash address 0x{crash_addr:x}: {new_region_entry}")
    logger.warning("If you suspect this region to be an mmio-region, manually preface it with 'mmio' to make sure that it is detected by fuzzware")
    add_missing_regions(config_map['memory_map'], new_region_entry)
    align_mem_map_to_pages(config_map['memory_map'])