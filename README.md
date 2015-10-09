# (D)DoS Attack Analysis
Our Pig Latin script (analysing_pcap.pig) uses https://github.com/packetloop/packetpig to perform a complete graphical analysis of (Distributed) Denial of Service [(D)DoS] attacks. Our assumption is that the input (.pcap file) contains a DDoS attack. So far our script focus only on attacks that generate a large amount of network traffic (volumetric attacks).

### Requirements
- Pig Latin;
- Python;
