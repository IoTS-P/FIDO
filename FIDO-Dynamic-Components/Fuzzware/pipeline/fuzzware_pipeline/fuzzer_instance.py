# from session import Session
from .run_fuzzer import run_fuzzer


class FuzzerInstance:
    session = None

    def __init__(self, session):
        self.session = session

    @property
    def fuzzer_output_dir(self):
        if self.session.num_fuzzer_procs == 1:
            return self.session.fuzzer_instance_dir(1)
        return self.session.fuzzers_dir

class LocalFuzzerInstance(FuzzerInstance):
    proc = None
    inst_num: int
    cmdline_args: list
    use_aflpp: bool

    def __init__(self, session, inst_num: int, use_aflpp: bool):
        super(LocalFuzzerInstance, self).__init__(session)
        self.cmdline_args = []
        print("Creating fuzzer instance with session: {}, inst_num: {}".format(session, inst_num))
        self.inst_num = inst_num
        self.use_aflpp = use_aflpp

    def start(self, silent=True):
        session_args = self.session.emulator_args()
        self.cmdline_args, self.proc = run_fuzzer(session_args, self.session.base_input_dir, self.fuzzer_output_dir, fuzzer_no=self.inst_num, fuzzers_total=self.session.num_fuzzer_procs, silent=silent, use_aflpp=self.use_aflpp)
        return True

    def kill(self):
        if self.proc:
            self.proc.terminate()
            self.proc.wait()
            self.proc = None

    def freeze(self):
        raise NotImplementedError()

    def unfreeze(self):
        raise NotImplementedError()

    def __str__(self):
        return "Local fuzzing instance.\nCommand line: {}".format(" ".join(self.cmdline_args))
