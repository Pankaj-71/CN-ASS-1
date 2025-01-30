import pyshark
import sys

# Capture live packets from a network interface (e.g., eth0)
cap = pyshark.LiveCapture(interface='lo')

# cap.sniff_continuously()
count=0

for pkt in cap.sniff_continuously():
    count+=1
    if count==10:
        break

print(count)




