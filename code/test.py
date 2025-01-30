import pyshark
import signal
import sys

# Flag to control capture stop
capture_flag = True

# Define a handler to catch KeyboardInterrupt signal
def signal_handler(sig, frame):
    global capture_flag
    capture_flag = False
    print("\nKeyboardInterrupt received, stopping capture...")

# Set up the signal handler
signal.signal(signal.SIGINT, signal_handler)

capture = pyshark.LiveCapture(interface='lo')

# Continuously sniff packets, checking for the flag
count = 0
for packet in capture.sniff_continuously():
    count+=1
    if not capture_flag:
        break  # Exit the loop if capture_flag is False


print(count)

