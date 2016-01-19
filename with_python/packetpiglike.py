
# coding: utf-8

# In[1]:

import argparse
import dpkt
import socket
import os

# In[2]:
parser = argparse.ArgumentParser()
parser.add_argument('-i', '--inputfile',
                    type=argparse.FileType('r'), 
                    help='output file, in JSON format')
parser.add_argument('-o', '--outputfile', 
                    nargs='?', 
                    type=argparse.FileType('w'), 
                    help='output file, in JSON format')
args = parser.parse_args()

inputfile = args.inputfile

if args.outputfile is not None:
    outputfile = args.outputfile 
else:
    outputfile = open(os.path.splitext(inputfile.name)[0]+'.txt','w')

# In[3]:

pcapfile = dpkt.pcap.Reader(inputfile)


# In[4]:

for ts, buf in pcapfile:
    eth = dpkt.ethernet.Ethernet(buf)

    #FILTERING ONLY FOR IP
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip = eth.data
        proto = ip.data

        ts = ts
        ip_version = ip.v
        ip_header_length = ip.hl
        ip_tos = ip.tos
        ip_total_length = ip.len
        ip_id = ip.id
        ip_flags = ip.opts
        ip_frag_offset = ip.off
        ip_ttl = ip.ttl
        ip_proto = ip.p
        ip_checksum = ip.sum
        ip_src  = socket.inet_ntoa(ip.src)
        ip_dst  = socket.inet_ntoa(ip.dst)
        #GETTING TCP INFORMATION
        tcp_sport = (proto.sport if ip.p == 6 else 0)
        tcp_dport = (proto.dport if ip.p == 6 else 0)
        tcp_seq_id = (proto.flags if ip.p == 6 else 0)
        tcp_ack_id = (proto.ack if ip.p == 6 else 0)
        tcp_offset = (proto.off if ip.p == 6 else 0)
        tcp_ns = (proto.seq if ip.p == 6 else 0)
        tcp_cwr = (int(( proto.flags & dpkt.tcp.TH_CWR ) != 0) if ip.p == 6 else 0)
        tcp_ece = (int(( proto.flags & dpkt.tcp.TH_ECE ) != 0) if ip.p == 6 else 0)
        tcp_urg = (int(( proto.flags & dpkt.tcp.TH_URG ) != 0) if ip.p == 6 else 0)
        tcp_ack = (int(( proto.flags & dpkt.tcp.TH_ACK ) != 0) if ip.p == 6 else 0)
        tcp_psh = (int(( proto.flags & dpkt.tcp.TH_PUSH) != 0) if ip.p == 6 else 0)
        tcp_rst = (int(( proto.flags & dpkt.tcp.TH_RST ) != 0) if ip.p == 6 else 0)
        tcp_syn = (int(( proto.flags & dpkt.tcp.TH_SYN ) != 0) if ip.p == 6 else 0)
        tcp_fin = (int(( proto.flags & dpkt.tcp.TH_FIN ) != 0) if ip.p == 6 else 0)
        tcp_window = (proto.win if ip.p == 6 else 0)
        tcp_len = (len(proto.data) if ip.p == 6 else 0)
        #GETTING UDP INFORMATION
        udp_sport = (proto.sport if ip.p == 17 else 0)
        udp_dport = (proto.dport if ip.p == 17 else 0)
        udp_len = (proto.ulen if ip.p == 17 else 0)
        udp_checksum = (proto.sum if ip.p == 17 else 0)
        
        print >> outputfile, ts,ip_version,ip_header_length,ip_tos,ip_total_length,ip_id,ip_flags,ip_frag_offset,ip_ttl,ip_proto,ip_checksum,ip_src,ip_dst,tcp_sport,tcp_dport,tcp_seq_id,tcp_ack_id,tcp_offset,tcp_ns,tcp_cwr,tcp_ece,tcp_urg,tcp_ack,tcp_psh,tcp_rst,tcp_syn,tcp_fin,tcp_window,tcp_len,udp_sport,udp_dport,udp_len,udp_checksum

        # if proto.dport == 80 and len(proto.data) > 0:
        #    http = dpkt.http.Request(proto.data)
        #    print http.len

