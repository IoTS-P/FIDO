# usage: DataTracker class is used to track the data of the device
import ctypes
class DataTracker:
    def __init__(self):
        self.dr = None # address of the data register
        self.callread_pc = None # the pc called the read function
        self.read_pc = None # call dr pc in the read function
        self.buffer_addr = None # the address reflected by the dr
        self.consume_pc_set = None # the set of the pc that consume the dr data
        self.irq_pc = None # the pc of the irq handler
        self.avail_pc = None # the pc to check the avail of the rx buffer (calculated by the irq handler or read_pc)
        # pointer to the rx buffer
        self.rx_head = None
        self.rx_tail = None
        self.buffer_len = 0
        self.buffer_min_len = None
        self.consume_count = 0
    
    def __eq__(self, other):
        if not isinstance(other, DataTracker):
            return NotImplemented
        return (
            self.callread_pc == other.callread_pc and
            self.dr == other.dr and
            self.read_pc == other.read_pc and
            self.buffer_addr == other.buffer_addr and
            self.irq_pc == other.irq_pc and
            self.avail_pc == other.avail_pc and
            self.rx_head == other.rx_head and
            self.rx_tail == other.rx_tail and
            self.buffer_len == other.buffer_len and
            self.buffer_min_len == other.buffer_min_len and
            self.consume_count == other.consume_count
        )
                   
    def __hash__(self):
        return hash((
            self.callread_pc,
            self.dr,
            self.read_pc,
            self.buffer_addr,
            self.irq_pc,
            self.avail_pc,
            self.rx_head,
            self.rx_tail,
            self.buffer_len,
            self.buffer_min_len,
            self.consume_count,
        ))
    
    def __str__(self):
        attrs = vars(self)
        import copy
        tmp_attrs = copy.deepcopy(attrs)
        for key, value in tmp_attrs.items():
            if isinstance(value, int):
                tmp_attrs[key] = hex(value)  # Convert integer value to hexadecimal format
        return '\n'.join("%s: %s" % item for item in tmp_attrs.items())


class StructDataTracker(ctypes.Structure):
    _fields_ = [
        ("dr", ctypes.c_uint32),
        ("callread_pc", ctypes.c_uint32),
        ("read_pc", ctypes.c_uint32),
        ("buffer_addr", ctypes.c_uint32),
        ("irq_pc", ctypes.c_uint32),
        ("avail_pc", ctypes.c_uint32),
        ("rx_head", ctypes.c_uint32),
        ("rx_tail", ctypes.c_uint32),
        ("buffer_len", ctypes.c_short),
        ("buffer_min_len", ctypes.c_short),
        ("irq_num", ctypes.c_short),
        ("consume_pcs", ctypes.c_char * 256),
        ("fifo", ctypes.c_uint8 * 4096),
        ("fifo_head", ctypes.c_short),
        ("fifo_tail", ctypes.c_short),
        ("interrupt_times", ctypes.c_int),
    ]

