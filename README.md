# packetpig_examples

Our PIG LATIN script (analysing_pcap.pig) is an extension of examples provided in https://github.com/packetloop/packetpig. Our goal is to generate graphical statistics about a Distributed Denial of Service (DDoS) attack that exists in a 'pcap' data file (input).

## Usage
pig -x local -f analysing_pcap.pig -p pcap=data/YourFile.pcap

## Visualizing the graphs
Before run you should uncomment and edit the last line of our script to move the output to your own Apache Server:

ex. "sh mv $outputFolder /Applications/MAMP/htdocs/""


