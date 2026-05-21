from queue import Queue
from time import time

from watchdog.events import FileSystemEventHandler


class NewConfigSnippetHandler(FileSystemEventHandler):
    queue: Queue

    def __init__(self, queue):
        super(NewConfigSnippetHandler, self).__init__()
        self.queue = queue

    def on_created(self, event):
        self.queue.put((time(), event.src_path))
