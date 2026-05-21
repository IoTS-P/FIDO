import os
from queue import Queue
from time import time

from fuzzware_pipeline.logging_handler import logging_handler
from fuzzware_pipeline.naming_conventions import INPUT_FILENAME_PREFIX
from watchdog.events import FileSystemEventHandler

logger = logging_handler().get_logger("pipeline")

class NewFuzzInputHandler(FileSystemEventHandler):
    queue: Queue

    def __init__(self, queue):
        super(NewFuzzInputHandler, self).__init__()
        self.queue = queue

    def on_created(self, event):
        path = event.src_path

        if os.path.split(path)[1].startswith(INPUT_FILENAME_PREFIX):
            self.queue.put((time(), path))
        else:
            logger.warning("NOT ADDING PATH (no input)")
