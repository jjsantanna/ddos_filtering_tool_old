#!/bin/bash

cd output_example

echo "Start,Folder,File_name,Duration[s],Peak[Mb/s],Protocol,Src_Ports,Dst_Ports,Src_IPs,IPs_Fragmented,Flags" > summary.csv

ls -d */ | while read folder_name; do 
	file_name=`echo $folder_name | awk -F "_" '{print $2}'| awk -F . '{print $1}'`

	cd $folder_name
	# first_time=`head pcap_filter2_stats/part-r-00000 |awk -F , '{cmd ="date -d @\""$1"\" +\"%d-%m-%Y %H:%M\" " ; cmd | getline var; print var; close(cmd) }'`
	first_time=`head pcap_filter2_stats/part-r-00000| awk -F , '{print $1}'`  
	duration_sec=`head pcap_filter2_stats/part-r-00000 |awk -F , '{print $3}'`
	peak_mbps=`cat pcap_mbps_pps/part-r-00000 | awk -F , '{print $2}'|sort -n |tail -1`
	protocol=`head -1 pcap_ip_proto/part-r-00000 | awk -F , '{print $1}'|awk -F ':' '{print $2}'`
	total_pkts=`cat pcap_filter2_sport/part-r-00000 |awk -F , '{s+=$4}END{print s}'`
	src_ports=`cat pcap_filter2_sport/part-r-00000 | awk -F , -v x=$total_pkts '{if($2/x > 0.25){printf $1"+";next;} else {count++; next;}} END {if(count >3){print "MANY"} else if(count >0 && count <=3){print "SOME"}}'` 
	dst_ports=`cat pcap_filter2_dport/part-r-00000 | awk -F , -v x=$total_pkts '{if($2/x > 0.25){printf $1"+";next;} else {count++; next;}} END {if(count >3){print "MANY"} else if(count >0 && count <=3){print "SOME"}}'`
	num_ips=`wc -l pcap_filter2_sip/part-r-00000|awk '{print $1}'`
	fragmented=`cat pcap_filter2_sip_stats/part-r-00000.csv |awk -F , '{if ($3 > 0) count++} END {print count}'`
	tcp_flags=`cat pcap_filter2_sip_stats/part-r-00000 |awk -F , '{if($16>0) countCWR++; if($17>0) countECE++; if($18>0) countURG++; if($19>0) countACK++; if($20>0) countPSH++; if($21>0) countRST++; if($22>0) countSYN++; if($23>0) countFIN++} END{if(countCWR>0) printf "CWR("countCWR")"; if(countECE>0) printf "ECE("countECE")";if(countURG>0) printf "URG("countURG")";if(countACK>0) printf "ACK("countACK")";if(countPSH>0) printf "PSH("countPSH")";if(countRST>0) printf "RST("countRST")";if(countSYN>0) printf "SYN("countSYN")";if(countFIN>0) printf "FIN("countFIN")";}'`
	
	cd ..
	echo $first_time,$folder_name,$file_name,$duration_sec,$peak_mbps,$protocol,$src_ports,$dst_ports,$num_ips,$fragmented,$tcp_flags >> temp.txt
	echo $first_time,$folder_name,$file_name,$duration_sec,$peak_mbps,$protocol,$src_ports,$dst_ports,$num_ips,$fragmented,$tcp_flags
done
sort -k1 -n temp.txt >>summary.csv
rm temp.txt

