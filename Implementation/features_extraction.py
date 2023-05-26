#Phase 1

from scapy.all import *
from decimal import Decimal

filename = 'pingfile.pcap'

# read in pcap file
packets = rdpcap(filename)

# initialize variables
total_fwd_pkts = 0
total_len_fwd_pkts = 0
fwd_pkt_len_max = 0
flow_pkts_per_sec = 0
fwd_pkts_per_sec = 0
pkt_len_variance = 0
prev_pkt_time = Decimal('0')

# loop through packets
for pkt in packets:

    # check if it's an IPv4 packet
    if IP in pkt:

        # check if it's a forward packet
        if pkt[IP].dst == '192.168.100.4':

            # update total forward packets
            total_fwd_pkts += 1

            # update total length of forward packets
            total_len_fwd_pkts += pkt[IP].len

            # update maximum length of forward packet
            fwd_pkt_len_max = max(fwd_pkt_len_max, pkt[IP].len)

            # calculate flow packets per second
            if pkt.time != prev_pkt_time:
                flow_pkts_per_sec += 1 / (pkt.time - prev_pkt_time)

            # calculate forward packets per second
            if prev_pkt_time != 0 and pkt.time != prev_pkt_time:
                fwd_pkts_per_sec += 1 / (pkt.time - prev_pkt_time)

            # update previous packet time
            prev_pkt_time = pkt.time

            # calculate packet length variance
            pkt_len_variance += (pkt[IP].len - pkt_len_variance) / total_fwd_pkts

# print results
print('Total Forward Packets:', total_fwd_pkts)
print("\n\n")
print('Total Length of Fwd Packets:', total_len_fwd_pkts)
print("\n\n")
print('Fwd Packet Length Max:', fwd_pkt_len_max)
print("\n\n")
print('Flow Packets/s:', flow_pkts_per_sec)
print("\n\n")
print('Fwd Packets/s:', fwd_pkts_per_sec)
print("\n\n")
print('Packet Length Variance:', pkt_len_variance)
print("\n\n")

#Phase2

#from scapy.all import *
from collections import defaultdict

# Define the list of features to extract
features = ['PSH Flag Count', 'Down/Up Ratio', 'Subflow Bwd Packets', 
            'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 'act_data_pkt_fwd', 
            'min_seg_size_forward']

# Read in the pcap file
packets = rdpcap(filename)

# Create a dictionary to store the feature values
results = defaultdict(list)

# Loop through each packet in the pcap file
for packet in packets:
    
    # Check if the packet has the necessary layers (TCP, IP) and destination IP is 192.168.100.4
    if TCP in packet and IP in packet and packet[IP].dst == '192.168.100.4':
        
        # Extract the relevant features from the packet
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        flags = packet[TCP].flags
        pkt_len = len(packet)
        
        # Calculate the Down/Up Ratio
        if src_ip < dst_ip:
            key = (src_ip, dst_ip, src_port, dst_port)
        else:
            key = (dst_ip, src_ip, dst_port, src_port)
        results[key].append(pkt_len)
        down = sum(results[key])
        up = pkt_len - down
        if up == 0:
            down_up_ratio = 0
        else:
            down_up_ratio = down / up
        
        # Calculate the PSH Flag Count
        psh_flag_count = 1 if flags & 0x08 else 0
        
        # Extract the other features from the packet
        subflow_bwd_packets = packet[TCP].ack
        subflow_bwd_bytes = packet[TCP].ack * packet[TCP].window
        init_win_bytes_forward = packet[TCP].window
        act_data_pkt_fwd = 1 if packet[TCP].payload else 0
        min_seg_size_forward = packet[TCP].options[0][1] if packet[TCP].options else 0
        
        # Store the feature values in the dictionary
        features_dict = {'PSH Flag Count': psh_flag_count,
                         'Down/Up Ratio': down_up_ratio,
                         'Subflow Bwd Packets': subflow_bwd_packets,
                         'Subflow Bwd Bytes': subflow_bwd_bytes,
                         'Init_Win_bytes_forward': init_win_bytes_forward,
                         'act_data_pkt_fwd': act_data_pkt_fwd,
                         'min_seg_size_forward': min_seg_size_forward}
        for feature in features:
            results[feature].append(features_dict[feature])

# Print the extracted feature values
for feature in features:
    print(feature, ":", results[feature])
    print("\n\n")

#Phase3

#from scapy.all import *
#from decimal import Decimal
from statistics import *

# read in the pcap file
packets = rdpcap(filename)

# initialize lists for storing feature values
flow_duration = []
flow_iat = []
fwd_iat = []
idle = []
flows = {}

# loop through packets
for pkt in packets:
    # only consider IP packets with the desired destination
    if IP in pkt and pkt[IP].dst == '192.168.100.4':
        # extract relevant fields
        src = pkt[IP].src
        dst = pkt[IP].dst
        protocol = pkt[IP].proto
        length = len(pkt)
        time = Decimal(pkt.time)

        # initialize or update per-flow state
        key = (src, dst, protocol)
        if key not in flows:
            flows[key] = {'start': time, 'prev_time': time, 'prev_len': length}
        else:
            flow = flows[key]
            flow_duration.append(time - flow['start'])
            flow_iat.append(time - flow['prev_time'])
            fwd_iat.append(time - flow['start'])
            flow['prev_time'] = time
            flow['prev_len'] = length

# compute feature statistics
flow_duration = [float(dur) for dur in flow_duration]  
flow_duration = [round(dur, 4) for dur in flow_duration]
if flow_iat:
    flow_iat_mean = Decimal(mean(flow_iat))
else:
    flow_iat_mean = 0
if len(flow_iat) > 0:
    flow_iat_max = Decimal(max(flow_iat))
else:
    # handle the case where flow_iat is empty
    flow_iat_max = 0
if fwd_iat:
    fwd_iat_mean = Decimal(mean(fwd_iat))
else:
    fwd_iat_mean = 0
if len(fwd_iat) > 0:
    fwd_iat_max = Decimal(max(flow_iat))
else:
    # handle the case where flow_iat is empty
    fwd_iat_max = 0
#fwd_iat_mean = Decimal(mean(fwd_iat))
#fwd_iat_max = Decimal(max(fwd_iat))
if len(idle) >= 2:
    idle_std = Decimal(stdev(idle))
else:
    idle_std = Decimal('0')

print("Flow Duration:", flow_duration)
print("\n\n")
print("Flow IAT Mean:", flow_iat_mean)
print("\n\n")
print("Flow IAT Max:", flow_iat_max)
print("\n\n")
print("Fwd IAT Mean:", fwd_iat_mean)
print("\n\n")
print("Fwd IAT Max:", fwd_iat_max)
print("\n\n")
print("Idle Std:", idle_std)
print("\n\n")
