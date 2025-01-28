from scapy.all import *

# call back functiion
count = 0
def packet_callback(packet):
    global count
    count=count+1
    print("No of pkts : ",count)

capture_pkts = []
def capturing():
    # int_face = input("Enter inface to capture packet : ")
    # rules = input("Enter filter rules. Example of some rules :\n 1. tcp\n 2. udp\n 3. tcp port 80\n 4. upd port 53\n 5. host <ip>\n 6. port <port_number>\n :")
    # sniff(prn=None, store=True, count=0, timeout=None, filter=None, iface=None, lfilter=None, opened_socket=None, **kwargs)
    sniff(prn=packet_callback, store=False, iface="lo", count=0)

if __name__ == "__main__":
    print("Hello")
    capturing()
    