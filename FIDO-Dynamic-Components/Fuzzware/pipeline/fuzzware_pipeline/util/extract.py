# pylint: skip-file
import sys
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from elftools.elf.constants import SH_FLAGS

def check_sig(filename):
    """
    reads the first 8 bytes of the file and checks for known header signatures
    Args:
        filename (string): name of the file
    Return:
        Corresponding signature or None
    """
    sig_data = b''
    with open(filename, "rb") as f:
        sig_data = f.read(8)

    for sig in signatures:
        if sig in sig_data:
            print("[+] Found a signature: " + sig.decode("utf-8"))
            return sig.decode("utf-8")

    print("[+] Found no known signatures, maybe it already is a flat binary")
    return

def extract_error():
    print("[xxx] Sorry something went wrong during extraction :-(")


#TODO debug/additional info
#######################
####### OAD ###########
#######################
OAD_HEADER_LEN = 42
OAD_ADD_HEADER_LEN = 8

def oad_boundary_info(payload):
    stack_entry = int.from_bytes(payload[0:0x4], "little")
    ICALL_STACK0_ADDR = int.from_bytes(payload[0x4:0x8], "little")
    RAM_START_ADDR = int.from_bytes(payload[0x8:0xc], "little")
    RAM_END_ADDR = int.from_bytes(payload[0xc:0x10], "little")

def oad_cont_info(payload, payload_len):
    img_segment_len = payload_len
    img_start_addr = int.from_bytes(payload, "little")

def oad_security_info(payload):
    version = payload[0]
    timestamp = int.from_bytes(payload[0x1:0x5], "little")
    sha2_hash = int.from_bytes(payload[0x5:0xd], "little")
    img_sig = int.from_bytes(payload[0xd:], "little")

def oad_parse_header(header):
    """
    Receives OAD header, parses it and returns the entry address of the binary
    Args:
        header (bytes): the first OEAD_HEADER_LEN bytes of the file
    Return:
        entry_addr (int): offset within the where the reset vector table is located
    """
    global OAD_HEADER_LEN
    oad_magic = header[0:0x8]
    crc = int.from_bytes(header[0x8:0xc], "little")
    bim_ver = header[0xc]
    header_ver = header[0xd]
    wireless_tech = int.from_bytes(header[0xe:0x10], "little")
    img_info = int.from_bytes(header[0x10:0x14], "little")
    img_val = int.from_bytes(header[0x14:0x18], "little")
    img_len = int.from_bytes(header[0x18:0x1c], "little")
    entry_addr = int.from_bytes(header[0x1c:0x20], "little")
    software_ver = int.from_bytes(header[0x20:0x24], "little")
    end_addr = int.from_bytes(header[0x24:0x28], "little")
    header_len = int.from_bytes(header[0x28:0x2a], "little")

    if header_len != OAD_HEADER_LEN:
        #happens if there is padding after the header data
        OAD_HEADER_LEN = header_len

    return entry_addr

def oad_parse_additional_headers(opt_headers):
    """
    Receives additional headers and analyzes them recursively
    Args:
        headers (bytes): additional header data
    """
    if opt_headers[0:8] == 8*b'\x00' or opt_headers[0:8] == 8*b'\xff':
        #only padding left
        return

    segment_type = opt_headers[0]
    wireless_tech = int.from_bytes(opt_headers[1:3], "little")
    reserved = opt_headers[3]
    payload_len = int.from_bytes(opt_headers[4:OAD_ADD_HEADER_LEN], "little")

    if segment_type == 0:
        #BOUNDARY INFORMATION
        oad_boundary_info(opt_headers[OAD_ADD_HEADER_LEN:(OAD_ADD_HEADER_LEN + payload_len)])

    elif segment_type == 1:
        #CONTIGUOS INFORMATION
        oad_cont_info(opt_headers[OAD_ADD_HEADER_LEN:OAD_ADD_HEADER_LEN+4], payload_len)
        payload_len = 4

    elif segment_type == 3:
        #SECURITY INFORMATION
        oad_security_info(opt_headers[OAD_ADD_HEADER_LEN:(OAD_ADD_HEADER_LEN + payload_len)])

    else:
        #UNKNOWN
        print("[!] FOUND UNKNOWN HEADER ... skipping")

    #check if there are enough bytes left for at least one more header
    if len(opt_headers[8+payload_len:]) >= 8:
        oad_parse_additional_headers(opt_headers[8+payload_len:])

    else:
        print("no more opt headers found")
        return

def oad_extract(filename):
    """
    Receives filename of an oad file and extracts a flat binary
    Args:
        filename (string): name of oad file
    """
    print("[+] OAD EXTRACT")
    data = b''
    with open(filename, "rb") as f:
        data = f.read()

    header = data[:OAD_HEADER_LEN]
    entry_addr = oad_parse_header(header)

    if entry_addr != OAD_HEADER_LEN:
        #There may be additional headers:
        oad_parse_additional_headers(data[OAD_HEADER_LEN:entry_addr])

    #extract
    #FOR OAD no extraction but instead return metadata?
    #ivt_offset = entry_addr
    #text is @ 0x0
    print("[!] No need to to extract this OAD img")
    print("[!] Make sure to set the 'ivt_offset' of the text segment in the config file to: 0x{:0x}".format(entry_addr))
    print("[!] The text segment starts at addr 0x0")
    print("[+] IVT at 0x{:x}".format(entry_addr))

    #pad to 4 bytes
    if len(data) & 0x3:
        f = open(filename, "ab")
        f.write((0x4 - (len(data) & 0x3))*b'\x00')
        f.close()

    return entry_addr


#######################
####### ELF ###########
#######################

def elf_extract(in_path):
    #elftools alternative
    if in_path.endswith(".elf"):
        #myfirmware.elf -> myfirmware.bin
        out_path = in_path[:-len(".elf")] + ".bin"
    else:
        #myfirmware -> myfirmware.bin
        out_path = in_path + ".bin"


    elffile = ELFFile(open(in_path, "rb"))
    segments = list()
    for segment_idx in range(elffile.num_segments()):
        segments.insert(segment_idx, dict())
        segments[segment_idx]['segment'] = elffile.get_segment(segment_idx)
        segments[segment_idx]['sections'] = list()

    alloc_sections = list() #all sections with alloc flag
    segment_sects = list() # all sections mapped(?) in segments

    for section_idx in range(elffile.num_sections()):
        section = elffile.get_section(section_idx)
        if section['sh_flags'] & SH_FLAGS.SHF_ALLOC:
            alloc_sections.append(section)
        for segment in segments:
            if segment['segment'].section_in_segment(section):
                segment['sections'].append(section)
                if section not in segment_sects:
                    segment_sects.append(section)

    if len(segment_sects) == len(alloc_sections): #better comparison??
        segments = sorted(segments, key = lambda x: x['segment'].header.p_paddr)
        dump_segments_to_file(segments, out_path, False)
    else:
        scatter_load(segments, alloc_sections, out_path)

    return 0 #vector offset table is always at 0x0

def scatter_load(segments, alloc_sections, out_path):
    #remove sections which are mapped through segments
    for segment in segments:
        for section in segment['sections']:
            if section in alloc_sections:
                alloc_sections.remove(section)
    #dump segments to file
    written_len = dump_segments_to_file(segments, out_path, True)

    #sort remaining allox sections by addr, if two are next to each other load them together
    alloc_sections = sorted(alloc_sections, key = lambda x: x.header.sh_addr)
    reduced_sections = list()
    do_reduce = False
    tmp_list = list()
    for i in range(len(alloc_sections) - 1):
        if not do_reduce:
            tmp_list.append(alloc_sections[i])
        cur_header = alloc_sections[i].header
        next_header = alloc_sections[i+1].header
        if cur_header.sh_addr + cur_header.sh_size == next_header.sh_addr:
            tmp_list.append(alloc_sections[i+1])
            do_reduce = True
        else:
            reduced_sections.append(sorted(tmp_list, key = lambda x: x.header.sh_addr))
            do_reduce = False
            tmp_list = list()

    if do_reduce:
        reduced_sections.append(sorted(tmp_list, key = lambda x: x.header.sh_addr))


    #now dump and save the offsets?
    virt_to_offset = {}
    f = open(out_path, "ab")
    for cur_sections in reduced_sections:
        virt_to_offset[cur_sections[0].header.sh_addr] = written_len
        for section in cur_sections:
            f.write(section.data())
            written_len += section.header.sh_size
        #page align
        if written_len % 0x1000:
            f.write(((0x1000 - (written_len % 0x1000))*b'\x00'))
            written_len += 0x1000 - (written_len % 0x1000)
    f.close()
    print("========")
    print(virt_to_offset)

    return virt_to_offset


def dump_segments_to_file(segments, out_path, align):
    reduced_segments = list() #only LOAD segments
    #can there be overlap between load segments? no??!?
    for segment in segments:
        if segment['segment'].header.p_type == "PT_LOAD":
            reduced_segments.append(segment)
        #overlap stuff maybe?

    #actual dumping:
    written_len = 0
    f = open(out_path, "wb")
    for segment in reduced_segments:
        cur_len = 0
        segment['sections'] = sorted(segment['sections'], key = lambda x: x.header.sh_addr)
        for section in segment['sections']:
            cur_len += section.header.sh_size
        written_len += cur_len
        if cur_len == segment['segment'].header.p_memsz:
            #no need to append 0s
            print("NOT APPENDING")
            for section in segment['sections']:
                if segment == reduced_segments[-1] and section == segment['sections'][-1] and section.data() == len(section.data())*b'\x00':
                    print("EDGE CASE")
                    written_len -= len(section.data())
                    break
                f.write(section.data())
        else:
            #append 0s!
            print("APPENDING")
            for section in segment['sections']:
                f.write(section.data())
            zeros = segment['segment'].header.p_memsz - cur_len
            written_len += zeros
            f.write(zeros*b'\x00')

    if align:
        #Align to page
        if written_len % 0x1000:
            f.write(((0x1000 - (written_len % 0x1000))*b'\x00'))
            written_len += 0x1000 - (written_len % 0x1000)

    f.close()
    return written_len


    pass


# Supported signatures
signatures = {
        b'OAD IMG': oad_extract,
        b'CC13x2r1': oad_extract,
        b'CC26x2R1': oad_extract,
        b'KAADAS': oad_extract,
        b'\x7f\x45\x4c\x46': elf_extract
        }


def is_extractable(filename):
    """
    Returns True if file can be extracted, else false
    """
    sig_data = b''
    with open(filename, "rb") as f:
        sig_data = f.read(8)

    for sig in signatures:
        if sig in sig_data:
            return True
    return False

def extract(filename):
    """
    REceives filename and tries to extract a flat binary binary from the file.
    Returns the entry address of the binary
    """
    sig_data = b''
    with open(filename, "rb") as f:
        sig_data = f.read(8)

    for sig in signatures:
        if sig in sig_data:
            entry_addr = signatures.get(sig, extract_error)(filename)
            break

    return entry_addr





def main():
    filename = sys.argv[1]
    check_sig(filename)
    extract(filename)

if __name__ == "__main__":main()
