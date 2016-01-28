
# coding: utf-8

# ###### Importing the needed libraries

# In[1]:

import argparse
import dpkt
import socket
import os


# ###### Defining the arguments to run the python script. Note that the while the 'inputfile' is required, the 'output' argument isn't.

# In[2]:

parser = argparse.ArgumentParser()
parser.add_argument('-i', '--inputfile',
                    type=argparse.FileType('r'), 
                    help='input file, in pcap format NOT pcapng or others')
parser.add_argument('-o', '--outputfile', 
                    nargs='?', 
                    type=argparse.FileType('w'), 
                    help='output file, in txt format')


# ###### Reading the arguments and dealing with the 'outputfile'

# In[3]:

args = parser.parse_args()
#args = parser.parse_args(['-i', 'prod-anon-001.pcap']) #example to test
inputfile = args.inputfile

if args.outputfile is not None:
    outputfile = args.outputfile 
else:
    outputfile = open(os.path.splitext(inputfile.name)[0]+'.txt','w')


# ###### Loading the 'inputfile' as a pcap file, via dpkt library.

# In[4]:

pcapfile = dpkt.pcap.Reader(inputfile)


# ###### Reading and Printing in the 'outputfile' the 33 information about the pcap file (in the same order as the output of packetpig)

# In[5]:

for ts, buf in pcapfile:
    eth = dpkt.ethernet.Ethernet(buf)

    #FILTERING ONLY FOR IP
    if eth.type == dpkt.ethernet.ETH_TYPE_IP:
        ip = eth.data #Loading the content of the ethernet into a variable 'ip'
        proto = ip.data #Loading the content of the 'ip' into a variable 'protocol' that can be for example ICMP, TCP, and UDP.
        ts = ts #1
        ip_version = ip.v #2
        ip_header_length = ip.hl #3
        ip_tos = ip.tos #4
        ip_total_length = ip.len #5
        ip_id = ip.id #6
        ip_flags = ip.opts #7
        #ip_frag_offset = ip.off & dpkt.ip.IP_OFFMASK #8 this field was removed because the more_fragments are more meaningful
        more_fragments = 1 if (int(ip.off & dpkt.ip.IP_MF)!= 0) else 0  #8 This flag is set to a 1 for all fragments except the last one
        ip_ttl = ip.ttl #9
        ip_proto = ip.p #10
        ip_checksum = ip.sum #11
        ip_src  = socket.inet_ntoa(ip.src) #12
        ip_dst  = socket.inet_ntoa(ip.dst) #13
        tcp_sport = (proto.sport if ip.p == 6 else 0) #14
        tcp_dport = (proto.dport if ip.p == 6 else 0) #15
        tcp_seq_id = (proto.flags if ip.p == 6 else 0) #16
        tcp_ack_id = (proto.ack if ip.p == 6 else 0) #17
        tcp_offset = (proto.off if ip.p == 6 else 0) #18
        tcp_ns = (proto.seq if ip.p == 6 else 0) #19
        tcp_cwr = (int(( proto.flags & dpkt.tcp.TH_CWR ) != 0) if ip.p == 6 else 0) #20
        tcp_ece = (int(( proto.flags & dpkt.tcp.TH_ECE ) != 0) if ip.p == 6 else 0) #21
        tcp_urg = (int(( proto.flags & dpkt.tcp.TH_URG ) != 0) if ip.p == 6 else 0) #22
        tcp_ack = (int(( proto.flags & dpkt.tcp.TH_ACK ) != 0) if ip.p == 6 else 0) #23
        tcp_psh = (int(( proto.flags & dpkt.tcp.TH_PUSH) != 0) if ip.p == 6 else 0) #24
        tcp_rst = (int(( proto.flags & dpkt.tcp.TH_RST ) != 0) if ip.p == 6 else 0) #25
        tcp_syn = (int(( proto.flags & dpkt.tcp.TH_SYN ) != 0) if ip.p == 6 else 0) #26
        tcp_fin = (int(( proto.flags & dpkt.tcp.TH_FIN ) != 0) if ip.p == 6 else 0) #27
        tcp_window = (proto.win if ip.p == 6 else 0) #28
        tcp_len = (len(proto.data) if ip.p == 6 else 0) #29
        udp_sport = (proto.sport if ip.p == 17 else 0) #30
        udp_dport = (proto.dport if ip.p == 17 else 0) #31
        udp_len = (proto.ulen if ip.p == 17 else 0) #32
        udp_checksum = (proto.sum if ip.p == 17 else 0) #33
 
        print >> outputfile, ts,ip_version,ip_header_length,ip_tos,ip_total_length,ip_id,ip_flags,more_fragments,ip_ttl,ip_proto,ip_checksum,ip_src,ip_dst,tcp_sport,tcp_dport,tcp_seq_id,tcp_ack_id,tcp_offset,tcp_ns,tcp_cwr,tcp_ece,tcp_urg,tcp_ack,tcp_psh,tcp_rst,tcp_syn,tcp_fin,tcp_window,tcp_len,udp_sport,udp_dport,udp_len,udp_checksum


# ###### TO-DO: before print the informations above, it will be interesting to add a few more information about the payload of the application =P

# In[6]:

# if proto.dport == 80 and len(proto.data) > 0:
#    http = dpkt.http.Request(proto.data)
#    print http.len

