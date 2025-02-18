import pyshark
import signal
import matplotlib.pyplot as plt
from collections import defaultdict
import json


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

count = 0
packet_sizes = [] # Packet data collection
total_data = 0  # Total data transferred in bytes

# Unique flows dictionary
flow_counts_src = defaultdict(int)  # {source_ip: count}
flow_counts_dst = defaultdict(int)  # {destination_ip: count}
flow_data = defaultdict(int)  # {(src_ip:port, dst_ip:port): data_transferred} & Unique src_ip:port->dst_ip:port
tmp_data = []
try:
    print("Press Ctrl+C to stop capturing and Proceed to Next Step")
    for packet in capture.sniff_continuously():
        count+=1
        if not capture_flag:
            break
        if hasattr(packet, 'ip'):
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
            
                src_port = packet[packet.transport_layer].srcport if (("TCP" in packet) or ("UDP" in packet)) else "unknown"
                dst_port = packet[packet.transport_layer].dstport if (("TCP" in packet) or ("UDP" in packet)) else "unknown"
            
                flow_key = f"{src_ip}:{src_port}"+"->"+f"{dst_ip}:{dst_port}"

                # Extract packet size
                size = int(packet.length)
                packet_sizes.append(size)
                total_data += size
                # Update counts
                flow_counts_src[src_ip] += 1
                flow_counts_dst[dst_ip] += 1
                flow_data[flow_key] += size  # Track data transferred per flow
        if hasattr(packet, 'tcp'):
            if (packet.ip.src=='127.0.0.1') & (packet.tcp.dstport=='25'):
                tmp_data.append(packet)
        if hasattr(packet, 'dns'):
            if hasattr(packet.dns, 'resp_name'):
                if packet.dns.resp_name=="routerswitches.com":
                    tmp_data.append(packet)

except Exception as e:
    print(f"Error: {e}")
finally:
    capture.close()  # Properly close the capture session

# Compute statistics
if packet_sizes:
        max_size = max(packet_sizes)
        min_size = min(packet_sizes)
        avg_size = sum(packet_sizes) / count
else:
    max_size = min_size = avg_size = 0
print(f"\nTotal Data Transferred: {total_data} bytes")
print(f"\nTotal Packets Transferred: {count} ")
print(f"Max Packet Size: {max_size} bytes")
print(f"Min Packet Size: {min_size} bytes")
print(f"Avg Packet Size: {avg_size:.2f} bytes")

#Unique source - Destination pairs with flow size in json file - 
with open("uniqu-source-desination.json", "w") as json_file:
    json.dump(flow_data, json_file, indent=4)
# Destination IP with Total Flow
with open("desination-total-flow.json", "w") as json_file:
    json.dump(flow_counts_dst, json_file, indent=4)
    
# source IP with Total flow json file
with open("source-total-flow.json", "w") as json_file:
    json.dump(flow_counts_src, json_file, indent=4)
    
# Plot histogram of packet sizes
plt.figure(figsize=(10, 6))
plt.hist(packet_sizes, bins=20, edgecolor='black', alpha=0.7)
plt.xlabel("Packet Size (bytes)")
plt.ylabel("Frequency")
plt.title("Packet Size Distribution")
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.savefig('graph.png', dpi=300)
plt.close()

# Max flow Connection Socket - 
# Find the flow that transferred the most data
most_data_flow = max(flow_data, key=flow_data.get, default=None)
most_data_transferred = flow_data[most_data_flow] if most_data_flow else 0
print("\nTop Data Transferring Flow:")
if most_data_flow:
    print(f"{most_data_flow}")
    print(f"Total Data Transferred: {most_data_transferred} bytes")
else:
    print("No significant data transfer recorded.")

with open('part2-answer-pkts.txt', 'w') as f:
    for item in tmp_data:
        print(item, file=f)
