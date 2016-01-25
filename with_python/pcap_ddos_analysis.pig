register lib_and_extras/datafu.jar
DEFINE MEDIAN datafu.pig.stats.StreamingMedian();
DEFINE VARIANCE datafu.pig.stats.VAR();

-- =========================================================
-- DEFINING CONSTANTS
-- =========================================================
%DEFAULT binsize 1 -- binsize for timeseries in second

-- =========================================================
-- PREPARING THE OUTPUT DIRECTORY
-- =========================================================
%DECLARE filePcap `basename $inputfile`;
%DEFAULT outputFolder 'output_example/TrafficAnalysis_$filePcap';

-- ##########################################################
-- Loading the pcap
-- ##########################################################
pcap = LOAD '$inputfile' using PigStorage(' ') AS (
    ts, -- 1
    ip_version:int, -- 2
    ip_header_length:int, --3
    ip_tos:int, -- 4
    ip_total_length:int, --5
    ip_id:int, --6
    ip_flags:int, --7
    --ip_frag_offset:int, -- 8 This field was substituted (from the packetpig) for the ip_more_fragments (bellow)
    ip_more_fragments:int, --8 
    ip_ttl:int, --9
    ip_proto:int, --10
    ip_checksum:int, --11
    ip_src:chararray, --12
    ip_dst:chararray, --13
    tcp_sport:int, --14
    tcp_dport:int, --15
    tcp_seq_id:long, --16
    tcp_ack_id:long, --17
    tcp_offset:int, --18
    tcp_ns:int,-- 19 
    tcp_cwr:int, --20
    tcp_ece:int, --21
    tcp_urg:int, --22
    tcp_ack:int, --23
    tcp_psh:int, --24
    tcp_rst:int, --25
    tcp_syn:int, --26
    tcp_fin:int, --27
    tcp_window:int, --28
    tcp_len:int, --29
    udp_sport:int, --30
    udp_dport:int, --31
    udp_len:int, --32
    udp_checksum:chararray --33
);

-- ##########################################################
-- Generating the time series of the raw pcap file.
-- Output columns:(1) timestamp, (2) data rate [Mb/s], and (3) packet rate [packets/s]
-- ##########################################################
pcap_mbps_pps = FOREACH (GROUP pcap BY (ts / $binsize * $binsize)) GENERATE 
        group as timestamp, 
        (float)(SUM(pcap.ip_total_length))*8/1000000 as mbits_per_bin,
        COUNT(pcap) as pkts_per_bin;

STORE pcap_mbps_pps INTO '$outputFolder/pcap_mbps_pps' USING PigStorage(',', '-schema');

-- ##########################################################
-- Generating the statistics of destination IP addresses (to find the target(s))
-- Output columns: (1) destination IP address and , (2) number of packets. SORTED decrescent by the number of packets 
-- ##########################################################
pkts_per_ip_dst = FOREACH (GROUP pcap BY ip_dst) GENERATE 
        group as ip_dst, 
        COUNT(pcap) as packets; -- considering that each line is a packet 

STORE (ORDER pkts_per_ip_dst BY packets DESC) INTO '$outputFolder/pcap_pkts_per_ip_dst' USING PigStorage(',', '-schema');

-- ##########################################################
-- Filtering the entire pcap file based on the destination IP address that most received packets (top1)
-- Output columns: the same 33 columns as in the original pcap
-- ##########################################################
top1_ip_dst = LIMIT (ORDER pkts_per_ip_dst BY packets DESC) 1;
pcap_filter1 = FILTER pcap BY (ip_dst == top1_ip_dst.ip_dst);

-- ##########################################################
-- Generating the statistics about the IP protocols (e.g., ICMP, TCP, UDP)
-- Output columns: (1) ip protocol number, (2) total number of occurrences
-- ##########################################################
pcap_filter1_ipproto = FOREACH (GROUP pcap_filter1 BY ip_proto)GENERATE 
        group as ip_proto, 
        COUNT(pcap_filter1) as occurrences;

-- ##########################################################
-- Loading an additional data wich contains the description of each IP protocol number
-- Output columns: (1) ip protocol number, (2) ip protocol description
-- ##########################################################
ipproto_desc = LOAD 'lib_and_extras/list_ipprotocol_number_desc.txt' USING PigStorage(',') AS (
        ip_proto_number:int, 
        ip_proto_desc:chararray);

-- ##########################################################
-- Join the statistics of IP protocol with the protocol description
-- Output columns: (1) ip protocol number, (2) ip protocol description
-- ##########################################################
pcap_filter1_ipproto_with_desc = FOREACH( JOIN pcap_filter1_ipproto BY ip_proto LEFT, ipproto_desc BY ip_proto_number) GENERATE 
        CONCAT((chararray)ip_proto,CONCAT(':',(chararray)ip_proto_desc)) as ip_proto, 
        occurrences as occurrences; 

STORE (ORDER pcap_filter1_ipproto_with_desc BY occurrences DESC) INTO '$outputFolder/pcap_ip_proto' USING PigStorage(',', '-schema');

-- ##########################################################
-- Filtering the pcap_filter1 based on the IP protocol that had most of the traffic (top 1)
-- Output columns: the same 33 columns as in the original pcap
-- ##########################################################
top1_ip_proto = LIMIT (ORDER pcap_filter1_ipproto BY occurrences DESC) 1;
pcap_filter2 = FILTER pcap_filter1 BY (ip_proto == top1_ip_proto.ip_proto);


-- ##########################################################
-- Generating list of src IP addresses involved in the attack
-- Output columns: 1) source IP
-- ##########################################################
pcap_filter2_sip = FOREACH (GROUP pcap_filter2 BY ip_src) GENERATE group;
STORE pcap_filter2_sip INTO '$outputFolder/pcap_filter2_sip' USING PigStorage(',');

-- ##########################################################
-- Getting the ASN for each source IP
-- ##########################################################
sh lib_and_extras/get_ans.sh '$outputFolder/pcap_filter2_sip';

pcap_filter2_sip_ans = LOAD '$outputFolder/pcap_filter2_sip/pcap_filter2_sip_ans.txt' USING PigStorage(';') AS (
        asn:chararray,
        ip:chararray, 
        bgp_prefix:chararray, 
        country:chararray, 
        as_info:chararray
    );

-- ##########################################################
-- Generating the source port number analysis over UDP
-- Output columns: (1) source port number, (2) occurrences over udp protocol
-- ##########################################################
pcap_filter2_pkt_udp_sport= FILTER pcap_filter2 BY udp_sport > 0;
pcap_filter2_total_pkt_udp_sport = FOREACH (GROUP pcap_filter2_pkt_udp_sport BY udp_sport) GENERATE 
        group as udp_src_port, 
        COUNT(pcap_filter2_pkt_udp_sport) as udp_packets;

-- ##########################################################
-- Generating the source port number analysis over TCP
-- Output columns: (1) source port number, (2) occurrences over tcp protocol
-- ##########################################################
pcap_filter2_pkt_tcp_sport= FILTER pcap_filter2 BY tcp_sport > 0;
pcap_filter2_total_pkt_tcp_sport = FOREACH (GROUP pcap_filter2_pkt_tcp_sport BY tcp_sport) GENERATE 
        group as tcp_src_port, 
        COUNT(pcap_filter2_pkt_tcp_sport) as tcp_packets;

-- ##########################################################
-- Grouping the source port number analysis of UDP and TCP
-- Output columns: (1) source port number, (2) occurrences over udp, (3) occurrences over tcp, (4) total number of packets 
-- ##########################################################
pcap_filter2_sport= FOREACH (JOIN pcap_filter2_total_pkt_udp_sport by udp_src_port FULL, pcap_filter2_total_pkt_tcp_sport BY tcp_src_port) GENERATE 
    (udp_src_port is null? tcp_src_port : udp_src_port) as src_port,
    (udp_packets is null ? 0 : udp_packets) as udp_packets,
    (tcp_packets is null ? 0 : tcp_packets) as tcp_packets,
    ((udp_packets is null ? 0 : udp_packets) + (tcp_packets is null ? 0 : tcp_packets)) as packets;

-- ##########################################################
-- Loading an additional data wich contains the description of port number
-- Output columns: (1) port number, (2) port description
-- ##########################################################
portnumber_desc = LOAD 'lib_and_extras/port_number_desc.txt' USING PigStorage(',') AS (
        port_number:int, 
        port_desc:chararray);

-- ##########################################################
-- Join the statistics of port number with the port description
-- Output columns: (1) ip protocol number, (2) ip protocol description
-- ##########################################################
pcap_filter2_sport_with_desc = FOREACH( JOIN pcap_filter2_sport BY src_port LEFT, portnumber_desc BY port_number) GENERATE 
        CONCAT((chararray)src_port,CONCAT(':',(chararray)(port_desc is null ? 'unknown' : port_desc))) as src_port, 
        udp_packets as udp_packets,
        tcp_packets as tcp_packets,
        packets as packets;

STORE (ORDER pcap_filter2_sport_with_desc BY packets DESC) INTO '$outputFolder/pcap_filter2_sport' USING PigStorage(',', '-schema');

-- ##########################################################
-- Generating the destination port number analysis over UDP
-- Output columns: (1) source port number, (2) occurrences over udp protocol
-- ##########################################################
pcap_filter2_pkt_udp_dport= FILTER pcap_filter2 BY udp_dport > 0;
pcap_filter2_total_pkt_udp_dport = FOREACH (GROUP pcap_filter2_pkt_udp_dport BY udp_dport) GENERATE 
        group as udp_dst_port, 
        COUNT(pcap_filter2_pkt_udp_dport) as udp_packets;

-- ##########################################################
-- Generating the destination port number analysis over TCP
-- Output columns: (1) source port number, (2) occurrences over tcp protocol
-- ##########################################################
pcap_filter2_pkt_tcp_dport= FILTER pcap_filter2 BY tcp_dport > 0;
pcap_filter2_total_pkt_tcp_dport = FOREACH (GROUP pcap_filter2_pkt_tcp_sport BY tcp_dport) GENERATE 
        group as tcp_dst_port, 
        COUNT(pcap_filter2_pkt_tcp_sport) as tcp_packets;

-- ##########################################################
-- Grouping the destination port number analysis over UDP and TCP
-- Output columns: (1) source port number, (2) occurrences over udp, (3) occurrences over tcp, (4) total number of packets 
-- ##########################################################
pcap_filter2_dport= FOREACH (JOIN pcap_filter2_total_pkt_udp_dport by udp_dst_port FULL, pcap_filter2_total_pkt_tcp_dport BY tcp_dst_port) GENERATE 
    (udp_dst_port is null ? tcp_dst_port : udp_dst_port) as dst_port,
    (udp_packets is null ? 0 : udp_packets) as udp_packets,
    (tcp_packets is null ? 0 : tcp_packets) as tcp_packets,
    ((udp_packets is null ? 0 : udp_packets) + (tcp_packets is null ? 0 : tcp_packets)) as packets;

-- ##########################################################
-- Join the statistics of port number with the port description
-- Output columns: (1) ip protocol number":"description, (2) occurrences over UDP, (3) occurrences over TCP, (4) total occurrences
-- ##########################################################
pcap_filter2_dport_with_desc = FOREACH( JOIN pcap_filter2_dport BY dst_port LEFT, portnumber_desc BY port_number) GENERATE 
        CONCAT((chararray)dst_port,CONCAT(':',(chararray)(port_desc is null ? 'unknown' : port_desc))) as dst_port,  
        udp_packets as udp_packets,
        tcp_packets as tcp_packets,
        packets as packets;

STORE (ORDER pcap_filter2_dport_with_desc BY packets DESC) INTO '$outputFolder/pcap_filter2_dport' USING PigStorage(',', '-schema');

-- ##########################################################
-- Generating the time series of the filtered pcap file.
-- Output columns:(1) timestamp, (2) data rate [Mb/s], and (3) packet rate [packets/s]
-- ##########################################################
pcap_filter2_mbps_pps = FOREACH (GROUP pcap_filter2 BY (ts / $binsize * $binsize)) GENERATE 
        group AS timestamp, 
        (float)(SUM(pcap_filter2.ip_total_length))*8/1000000 AS mbits_per_bin,
        COUNT(pcap_filter2) AS pkts_per_bin;

STORE pcap_filter2_mbps_pps INTO '$outputFolder/pcap_filter2_mbps_pps' USING PigStorage(',', '-schema');

-- ##########################################################
-- Generating the overall statistics of the filtered pcap file.
-- Output columns:(1) first timestamp, (2) last timestamp, (3) duration, (4,5,6) avg, median, std dev of packet rate [pckt/s], (7,8,9) avg, median, vstd dev of bit rate [Mb/s]
-- ##########################################################
pcap_filter2_stats = FOREACH (GROUP pcap_filter2_mbps_pps ALL) GENERATE 
        MIN(pcap_filter2_mbps_pps.timestamp) AS first_ts,
        MAX(pcap_filter2_mbps_pps.timestamp) AS last_ts,
        MAX(pcap_filter2_mbps_pps.timestamp) - MIN(pcap_filter2_mbps_pps.timestamp) AS duration,
        AVG(pcap_filter2_mbps_pps.mbits_per_bin) AS avg_mbps_pcap_filter2,
        FLATTEN(MEDIAN(pcap_filter2_mbps_pps.mbits_per_bin)) AS median_mbps_pcap_filter2,
        SQRT(VARIANCE(pcap_filter2_mbps_pps.mbits_per_bin)) AS std_dev_mbps_pcap_filter2,
        AVG(pcap_filter2_mbps_pps.pkts_per_bin) AS avg_pps_pcap_filter2,
        FLATTEN(MEDIAN(pcap_filter2_mbps_pps.pkts_per_bin)) AS median_pps_pcap_filter2,
        SQRT(VARIANCE(pcap_filter2_mbps_pps.pkts_per_bin)) AS std_pps_dev_pcap_filter2;

STORE pcap_filter2_stats INTO '$outputFolder/pcap_filter2_stats' USING PigStorage(',', '-schema');

-- ##########################################################
-- Generating the statistics for each source IP address
-- Output columns: (1) source IP address, (2) the total number of packets, (3) packets marked as more fragments (4) packets NON marked as more fragments (5) num of distinct source ports (6) num of distinct destination ports (7,8,9,10,11) avg, min, max, median, and std of the packet lenght [bytes] (12,12,13,15) Avg, min, max, std of the TTL (16-23) number of occurrences of TCP flags
-- ##########################################################
pcap_filter2_sip_stats = FOREACH (GROUP pcap_filter2 BY ip_src) {
    total_packets = COUNT(pcap_filter2);
    fragmented_packets = FILTER pcap_filter2 BY (ip_more_fragments > 0);
    packets_fragment_marked = COUNT(fragmented_packets);
    distinct_udp_sport = DISTINCT pcap_filter2.udp_sport;
    distinct_tcp_sport = DISTINCT pcap_filter2.tcp_sport;
    distinct_udp_dport = DISTINCT pcap_filter2.udp_dport;
    distinct_tcp_dport = DISTINCT pcap_filter2.tcp_dport;

    GENERATE 
        group AS src_ip, --1
        --
        total_packets as total_packets, --2
        packets_fragment_marked as packets_fragment_marked, --3
        (total_packets-packets_fragment_marked) as packets_frag_non_marked, --4
        --
        -- distinct_udp_sport AS distinct_udp_sport,
        -- distinct_tcp_sport AS distinct_tcp_sport,
        (COUNT(distinct_udp_sport)+COUNT(distinct_tcp_sport)-1) AS num_distinct_sport, --5
        (COUNT(distinct_udp_dport)+COUNT(distinct_tcp_dport)-1) AS num_distinct_dport, --6
        --
        AVG(pcap_filter2.ip_total_length) AS pkt_length_avg, --7
        MIN(pcap_filter2.ip_total_length) AS pkt_length_min, --8
        MAX(pcap_filter2.ip_total_length) AS pkt_length_max, --8
        FLATTEN(MEDIAN(pcap_filter2.ip_total_length)) AS pkt_length_median, --10
        SQRT(VARIANCE(pcap_filter2.ip_total_length)) AS pkt_length_std_dev, --11
        --
        AVG(pcap_filter2.ip_ttl) AS ttl_avg, --12
        MIN(pcap_filter2.ip_ttl) AS ttl_min, --13
        MAX(pcap_filter2.ip_ttl) AS ttl_max, --14
        SQRT(VARIANCE(pcap_filter2.ip_ttl)) AS ttl_std_dev,--15
        --
        SUM(pcap_filter2.tcp_cwr) AS CWR,--16
        SUM(pcap_filter2.tcp_ece) AS ECE,--17
        SUM(pcap_filter2.tcp_urg) AS URG,--18
        SUM(pcap_filter2.tcp_ack) AS ACK,--19
        SUM(pcap_filter2.tcp_psh) AS PSH,--20
        SUM(pcap_filter2.tcp_rst) AS RST,--21
        SUM(pcap_filter2.tcp_syn) AS SYN,--22
        SUM(pcap_filter2.tcp_fin) AS FIN;--23
};

-- ##########################################################
-- Generating the timeseries (data and packet rate) of each source IP address (all together)
-- Output columns: (1) source IP address (2) timestamp (3) data rate [Mb/s] (4) packet rate [pckt/s]
-- ##########################################################
pcap_filter2_sip_mbps_pps = FOREACH (GROUP pcap_filter2 BY (ip_src, (ts / $binsize * $binsize))) GENERATE 
        FLATTEN(group) AS (src_ip,bin),
        (float)(SUM(pcap_filter2.ip_total_length))*8/1000000 AS mbits_per_bin,
        COUNT(pcap_filter2) AS pkts_per_bin;

STORE (ORDER pcap_filter2_sip_mbps_pps BY bin) INTO '$outputFolder/pcap_filter2_sip_mbps_pps' USING PigStorage(',', '-schema');

-- ##########################################################
-- Generating the statistics of each source IP address (all together)
-- Output columns: (1) source IP address (2) timestamp (3) data rate [Mb/s] (4) packet rate [pckt/s]
-- ##########################################################
pcap_filter2_sip_mbps_pps_statistics = FOREACH (GROUP pcap_filter2_sip_mbps_pps BY src_ip) GENERATE 
        group AS src_ip,
        AVG(pcap_filter2_sip_mbps_pps.mbits_per_bin) AS mbits_per_bin_avg,
        AVG(pcap_filter2_sip_mbps_pps.pkts_per_bin) AS pkts_per_bin_avg;

-- ##########################################################
-- Join the general statistics of source IPs with their data and packet rate statistics
-- Output columns: 
-- ##########################################################
pcap_filter2_sip_stats_joined = FOREACH (JOIN pcap_filter2_sip_stats BY src_ip LEFT, pcap_filter2_sip_mbps_pps_statistics BY src_ip) GENERATE 
        pcap_filter2_sip_stats::src_ip AS src_ip,
        total_packets AS total_packets, --2
        packets_fragment_marked AS packets_fragment_marked, --3
        packets_frag_non_marked AS packets_frag_non_marked, --4
        num_distinct_sport AS num_distinct_sport, --5
        num_distinct_dport AS num_distinct_dport, --6
        pkt_length_avg AS pkt_length_avg, --7
        pkt_length_min AS pkt_length_min, --8
        pkt_length_max AS pkt_length_max, --9
        pkt_length_median AS pkt_length_median, --10
        pkt_length_std_dev AS pkt_length_std_dev, --11
        ttl_avg AS ttl_avg, --12
        ttl_min AS ttl_min, --13
        ttl_max AS ttl_max, --14
        ttl_std_dev AS ttl_std_dev,--15
        CWR AS CWR,--16
        ECE AS ECE,--17
        URG AS URG,--18
        ACK AS ACK,--19
        PSH AS PSH,--20
        RST AS RST,--21
        SYN AS SYN,--22
        FIN AS FIN,--23
        mbits_per_bin_avg AS mbits_per_bin_avg, --24
        pkts_per_bin_avg AS pkts_per_bin_avg; --25


-- ##########################################################
-- Joining the statistics of source IPs with their ASN
-- ##########################################################
pcap_filter2_sip_stats_asn = FOREACH (JOIN pcap_filter2_sip_stats_joined BY src_ip LEFT, pcap_filter2_sip_ans BY ip) GENERATE 
        src_ip AS src_ip,
        total_packets AS total_packets, --2
        packets_fragment_marked AS packets_fragment_marked, --3
        packets_frag_non_marked AS packets_frag_non_marked, --4
        num_distinct_sport AS num_distinct_sport, --5
        num_distinct_dport AS num_distinct_dport, --6
        pkt_length_avg AS pkt_length_avg, --7
        pkt_length_min AS pkt_length_min, --8
        pkt_length_max AS pkt_length_max, --9
        pkt_length_median AS pkt_length_median, --10
        pkt_length_std_dev AS pkt_length_std_dev, --11
        ttl_avg AS ttl_avg, --12
        ttl_min AS ttl_min, --13
        ttl_max AS ttl_max, --14
        ttl_std_dev AS ttl_std_dev,--15
        CWR AS CWR,--16
        ECE AS ECE,--17
        URG AS URG,--18
        ACK AS ACK,--19
        PSH AS PSH,--20
        RST AS RST,--21
        SYN AS SYN,--22
        FIN AS FIN,--23
        mbits_per_bin_avg AS mbits_per_bin_avg, --24
        pkts_per_bin_avg AS pkts_per_bin_avg, --25
        asn AS asn, --26
        bgp_prefix AS bgp_prefix, --27
        country AS country, --28 
        as_info AS as_info; --29
STORE (ORDER pcap_filter2_sip_stats_asn BY total_packets DESC) INTO '$outputFolder/pcap_filter2_sip_stats' USING PigStorage(',', '-schema');

-- ##########################################################
-- Generating statistics about the ASes
-- ##########################################################
pcap_filter2_country_stats = FOREACH (GROUP pcap_filter2_sip_stats_asn BY country) GENERATE 
    (group is null ? 'NONE' : group) AS country,
    COUNT(pcap_filter2_sip_stats_asn.src_ip) AS sips;
STORE (ORDER pcap_filter2_country_stats BY sips DESC) INTO '$outputFolder/pcap_filter2_country_stats' USING PigStorage(',', '-schema');;

-- ##########################################################
-- Generating statistics about BGP prefixes
-- ##########################################################
pcap_filter2_bgp_stats = FOREACH (GROUP pcap_filter2_sip_stats_asn BY bgp_prefix) GENERATE 
    (group is null ? 'NONE' : group) AS bgp_prefix,
    COUNT(pcap_filter2_sip_stats_asn.src_ip) AS sips;
STORE (ORDER pcap_filter2_bgp_stats BY sips DESC) INTO '$outputFolder/pcap_filter2_bgp_stats' USING PigStorage(',', '-schema');;

-- ##########################################################
-- Generating statistics about BGP prefixes
-- ##########################################################
pcap_filter2_asn_stats = FOREACH (GROUP pcap_filter2_sip_stats_asn BY asn) GENERATE 
    (group is null ? 'NONE' : group) AS asn,
    COUNT(pcap_filter2_sip_stats_asn.src_ip) AS sips;
STORE (ORDER pcap_filter2_asn_stats BY sips DESC) INTO '$outputFolder/pcap_filter2_asn_stats' USING PigStorage(',', '-schema');;

-- ##########################################################
-- Generating CSV files of the outputs. By default PIG outputs 2 files in a folder: "_SUCESS" and "part-r-00000" (results) AND among others HIDDEN files ".pig_header" and ".pig_schema". Then we wrote a code "preparing_csv.sh" to make a csv file based on the results including the header.
-- ##########################################################
sh lib_and_extras/preparing_csv.sh '$outputFolder'

-- ##########################################################
-- Copying the html that plots all the results with Google Charts
-- ##########################################################
sh cp lib_and_extras/DataAnalysis.html $outputFolder/index.html
sh cp lib_and_extras/jquery.csv-0.71.js $outputFolder/

-- ##########################################################
-- TIP: after you finish all the steps you can see the results doing the following steps
-- ##########################################################
-- 1) In a command line, go to the folder that you placed all the output folders (e.g., TrafficAnalysis_prod-anon-001.txt/) 
--      $ cd TrafficAnalysis_prod-anon-001.txt/
-- 2) Considering you are inside the output_folder, start a simple HTTP server in a generic port (e.g., 12345)
--      $ python -m SimpleHTTPServer 12345
-- 3) Open a browser and access the localhost and the port that you setup in the previous step. OR simply type on command line
--      $ open http://localhost:12345
--
-- ANOTHER OPTION is to copy the results to your apache server and run directly from there
-- sh mv $outputFolder /Applications/MAMP/htdocs/
-- sh open http://localhost:8887/TrafficAnalysis_$filePcap
