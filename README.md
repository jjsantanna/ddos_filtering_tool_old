# (D)DoS Attack Analysis

- Goal: the analysis of network characteristics, given that it contains a (D)DoS attack.
- Input: .pcap file
- Output: a graphical analysis of the attack

## First option: Using packetpig
In the beginning we used a library developed by packetloop, called [packetpig](https://github.com/packetloop/packetpig). Such library is very good however it is a bit restricted related to (1) get the payload of packets, (2) to read pcapng file, and (3) to read pcap files with missing bytes. If the data that you want to visualize doesn't have any one of the three restriction, we DO recomment packetpig.

## Second option: Using python
To overcome the limitations of packetpig we wrote a python script to


This Pig Latin script (analysing_pcap.pig) performs an analysis of (Distributed) Denial of Service [(D)DoS] attacks. We assume the input file (.pcap) contains a DDoS attack which generated a large amount of network traffic (volumetric attacks). [we will add in the future the analysis of application layer attacks]

By considering the input file (.pcap) contains both a DDoS attack and a normal traffic, we must first to filter only the attack. To do so we perfom three filters depicted in the sketch bellow. The Filter I refines the Full Traffic to the traffic that has only the most target destination IP address. After that, the Filter II is applied to isolate only the IP protocol the attack is based on. Finally, we analyse the payload similarity considering the remaining traffic of Filter I and II [^1]. 

[^1]: The Payload similarity (Filter III) is not implemented YET.

![Sketch of Our Approach](data/sketch.png)

### Requirements
- Apache Pig;
- Python;

It doesn't work with pcap-ng. Sometimes a file with extension pcap actually is a pcap-ng. You can discover the type of a pcap with "$ capinfos <file>.pcap |grep type". You convert a pcap-ng with "$ editcap -F libpcap <file>.pcapng <file>.pcap". 

pig -x local -f analysing_pcap.pig -p pcap=<test>.pcap


With packet pig
