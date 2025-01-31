import pyshark
import signal
import matplotlib.pyplot as plt
from collections import defaultdict

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
# count = 0
# for packet in capture.sniff_continuously():
#     count+=1
#     if not capture_flag:
#         break  # Exit the loop if capture_flag is False

count = 0
# Packet data collection
packet_sizes = []
total_data = 0  # Total data transferred in bytes

# try:
#     for packet in capture.sniff_continuously():
#         count+=1
#         if not capture_flag:
#             break
        
#         # Extract packet size if available
#         if hasattr(packet, 'length'):
#             size = int(packet.length)
#             packet_sizes.append(size)
#             total_data += size  # Accumulate total data
        
# except Exception as e:
#     print(f"Error: {e}")
# finally:
#     capture.close()  # Properly close the capture session

# # Compute statistics
# if packet_sizes:
#     max_size = max(packet_sizes)
#     min_size = min(packet_sizes)
#     avg_size = sum(packet_sizes) / len(packet_sizes)
# else:
#     max_size = min_size = avg_size = 0

# # Print results
# print(f"\nTotal Data Transferred: {total_data} bytes")
# print(f"\nTotal Packet Transferred: {count}")
# print(f"Max Packet Size: {max_size} bytes")
# print(f"Min Packet Size: {min_size} bytes")
# print(f"Avg Packet Size: {avg_size:.2f} bytes")

# # Plot histogram
# plt.figure(figsize=(10, 6))
# plt.hist(packet_sizes, bins=30,edgecolor='black', alpha=0.7)
# plt.xlabel("Packet Size (bytes)")
# plt.ylabel("Frequency")
# plt.title("Packet Size Distribution")
# plt.grid(axis='y', linestyle='--', alpha=0.7)
# plt.show()

# Unique flows dictionary
flow_counts_src = defaultdict(int)  # {source_ip: count}
flow_counts_dst = defaultdict(int)  # {destination_ip: count}
flow_data = defaultdict(int)  # {(src_ip:port, dst_ip:port): data_transferred} & Unique src_ip:port->dst_ip:port

try:
    for packet in capture.sniff_continuously():
        count+=1
        if not capture_flag:
            break
        
        # Extract packet information if available
        if hasattr(packet, 'ip'):
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            
            # Extract port numbers (if available in TCP/UDP packets)
            src_port = packet[packet.transport_layer].srcport if hasattr(packet, 'transport_layer') else "unknown"
            dst_port = packet[packet.transport_layer].dstport if hasattr(packet, 'transport_layer') else "unknown"
            
            flow_key = (f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}")

            # Extract packet size
            size = int(packet.length)
            packet_sizes.append(size)
            total_data += size

            # Update counts
            flow_counts_src[src_ip] += 1
            flow_counts_dst[dst_ip] += 1
            flow_data[flow_key] += size  # Track data transferred per flow

except Exception as e:
    print(f"Error: {e}")
finally:
    capture.close()  # Properly close the capture session

# Compute statistics
if packet_sizes:
    max_size = max(packet_sizes)
    min_size = min(packet_sizes)
    avg_size = sum(packet_sizes) / len(packet_sizes)
else:
    max_size = min_size = avg_size = 0

# Find the flow that transferred the most data
most_data_flow = max(flow_data, key=flow_data.get, default=None)
most_data_transferred = flow_data[most_data_flow] if most_data_flow else 0

# Print results
print(f"\nTotal Data Transferred: {total_data} bytes")
print(f"\nTotal Packets Transferred: {count} ")
print(f"Max Packet Size: {max_size} bytes")
print(f"Min Packet Size: {min_size} bytes")
print(f"Avg Packet Size: {avg_size:.2f} bytes")

# # Unique source-destination pairs (source IP:port destination IP:port)
# print("\nUnique source-destination pairs (source IP:port destination IP:port)")
# for flow_key, num in flow_data.items():
#     print(f"Src-IP:port Des-IP:port {flow_key}")

print("\nSource IP Flow Counts:")
for ip, count in flow_counts_src.items():
    print(f"{ip}: {count} flows")

print("\nDestination IP Flow Counts:")
for ip, count in flow_counts_dst.items():
    print(f"{ip}: {count} flows")

print("\nTop Data Transferring Flow:")
if most_data_flow:
    print(f"Source: {most_data_flow[0]} -> Destination: {most_data_flow[1]}")
    print(f"Total Data Transferred: {most_data_transferred} bytes")
else:
    print("No significant data transfer recorded.")

# Plot histogram of packet sizes
plt.figure(figsize=(10, 6))
plt.hist(packet_sizes, bins=20, edgecolor='black', alpha=0.7)
plt.xlabel("Packet Size (bytes)")
plt.ylabel("Frequency")
plt.title("Packet Size Distribution")
plt.grid(axis='y', linestyle='--', alpha=0.7)
plt.show()

