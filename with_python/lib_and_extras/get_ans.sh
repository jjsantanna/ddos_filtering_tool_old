#!/bin/bash

folder=$1
#folder='/Users/santannajj/Desktop/b/pcap_nbip_copy/pcap_ddos_analysis/with_python/output_example/TrafficAnalysis_prod-anon-001.txt/pcap_filter2_sip'

echo -e 'begin\ncountrycode\nprefix\nnoheader' > $folder/tmp
cat $folder/part-r-00000 >> $folder/tmp
echo 'end' >> $folder/tmp
netcat whois.cymru.com 43 < $folder/tmp| tail -n +2 |awk -F '|' '{gsub(/ /, "", $0); gsub(",", "-", $5); print $1";"$2";"$3";"$4";"$5} ' > $folder/pcap_filter2_sip_ans.txt
rm $folder/tmp
