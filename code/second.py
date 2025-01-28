import pyshark

# Capture live packets from a network interface (e.g., eth0)
cap = pyshark.LiveCapture(interface='lo')

# Capture 5 packets
count=0
for packet in cap.sniff_continuously():
    count+=1
    print(count)
    print(packet)
