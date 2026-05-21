from queue import Queue
from time import time
import os
from fuzzware_pipeline.naming_conventions import PREFIX_STATEFILE

from watchdog.events import FileSystemEventHandler


class NewMmioStateHandler(FileSystemEventHandler):
    queue: Queue

    def __init__(self, queue):
        super(NewMmioStateHandler, self).__init__()
        self.queue = queue

    def on_created(self, event):
        if PREFIX_STATEFILE in os.path.basename(event.src_path):
            self.queue.put((time(), event.src_path))
