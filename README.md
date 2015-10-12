# (D)DoS Attack Analysis
Our Pig Latin script (analysing_pcap.pig) performs a graphical analysis of (Distributed) Denial of Service [(D)DoS] attacks. We assume the input file (.pcap) contains a DDoS attack which generated a large amount of network traffic (volumetric attacks). 

By considering the input file (.pcap) contains both a DDoS attack and a normal traffic, we must first to isolate only the attack. To do so we perfom three filters depicted in the sketch bellow. The Filter I refines the Full Traffic to the traffic that has only the most target destination IP address. After that, the Filter II is applied to isolate only the IP protocol the attack is based on. Finally, we analyse the payload similarity considering the remaining traffic of Filter I and II [^1]. 

[^1]: The Payload similarity (Filter III) is not implemented YET.

![Sketch of Our Approach](data/sketch.png)

### Requirements
- Apache Pig;
- Python;
