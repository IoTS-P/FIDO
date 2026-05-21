from queue import Queue
from time import time

from watchdog.events import FileSystemEventHandler


class NewTraceFileHandler(FileSystemEventHandler):
    queue: Queue

    def __init__(self, queue):
        super(NewTraceFileHandler, self).__init__()
        self.queue = queue

    def on_created(self, event):
        self.queue.put((time(), event.src_path))
