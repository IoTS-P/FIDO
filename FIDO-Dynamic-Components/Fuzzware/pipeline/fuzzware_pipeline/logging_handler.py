# pylint: skip-file

import logging
import os
import sys
import inspect

LOG_DATE_FOMAT = "%m-%d %H:%M:%S"
class logging_handler():

    class __logging_handler():
        def __init__(self):
            self.FORMAT = logging.Formatter('[%(asctime)s %(levelname)s] %(message)s', LOG_DATE_FOMAT)
            self.logger = {}

        def get_logger(self, name):
            if name not in self.logger:
                self.logger[name] = logger(name)
            return self.logger[name]

    #instance of __logging_handler()
    instance = None

    # Singleton design pattern
    def __new__(cls):
        if not logging_handler.instance:
            logging_handler.instance = logging_handler.__logging_handler()
        return logging_handler.instance


class logger():
    def __init__(self, name):
        self.logger = logging.getLogger(name)
        self.output_file = None
        self.logger.propagate = False
        self.message_buffer = self.create_message_buffer()
        self.terminal_only = False
        self.stream_handler = None

        self.config_stream_handler()
        self.logger.setLevel(logging.DEBUG)

    def create_message_buffer(self):
        message_buffer = {}
        message_buffer["functions"] = {}

        message_buffer["functions"]["info"] = self.logger.info
        message_buffer["functions"]["warning"] = self.logger.warning
        message_buffer["functions"]["error"] = self.logger.error
        message_buffer["functions"]["debug"] = self.logger.debug

        message_buffer["messages"] = []
        return message_buffer

    def set_terminal_only(self):
        self.terminal_only = True
        self.clear_message_buffer()

    def config_stream_handler(self):
        self.stream_handler = logging.StreamHandler(sys.stdout)
        self.set_format_and_loglevel(self.stream_handler, logging.INFO)
        self.logger.addHandler(self.stream_handler)

    def set_log_file(self, output_file):
        filehandler = logging.FileHandler(f"{output_file}.log", "a", "utf-8")
        self.set_format_and_loglevel(filehandler, logging.DEBUG)
        self.logger.addHandler(filehandler)
        self.output_file = output_file

    def set_output_file(self, project_dir, filename):
        log_dir = self.determine_log_dir_from_directory(project_dir)
        output_file = os.path.join(log_dir, filename)
        self.set_log_file(output_file)

        if self.message_buffer["messages"]:
            self.logger.removeHandler(self.stream_handler)
            self.log_and_clean_message_buffer()
            self.logger.addHandler(self.stream_handler)

    def determine_log_dir_from_directory(self, directory):
        log_dir = os.path.join(directory, 'logs')
        return log_dir

    def set_format_and_loglevel(self, handler, level):
        handler.setFormatter(logging_handler().FORMAT)
        handler.setLevel(level)

    def append_to_message_buffer(self, msg, level):
        self.message_buffer["messages"].append({"msg": msg, "level": level})

    def clear_message_buffer(self):
        self.message_buffer["messages"] = []

    def log_and_clean_message_buffer(self):
        for message in self.message_buffer["messages"]:
            msg = message["msg"]
            level = message["level"]
            self.message_buffer["functions"][level](msg)
        self.clear_message_buffer()

    def maybe_buffer(self, level, msg):
        if self.output_file == None and not self.terminal_only:
            self.append_to_message_buffer(msg, level)

    def error(self, msg):
        filename = self.get_caller_info(inspect.stack()[1])
        msg = f"{filename} - {msg}"

        self.maybe_buffer("error", msg)

        self.logger.error(msg)

    def warning(self, msg):
        filename = self.get_caller_info(inspect.stack()[1])
        msg = f"{filename} - {msg}"

        self.maybe_buffer("warning", msg)

        self.logger.warning(msg)

    def info(self, msg):
        filename = self.get_caller_info(inspect.stack()[1])
        msg = f"{filename} - {msg}"

        self.maybe_buffer("info", msg)

        self.logger.info(msg)

    def debug(self, msg):
        filename = self.get_caller_info(inspect.stack()[1])
        msg = f"{filename} - {msg}"

        self.maybe_buffer("debug", msg)

        self.logger.debug(msg)

    def get_caller_info(self, caller_frame):
        return os.path.basename(caller_frame.filename)
