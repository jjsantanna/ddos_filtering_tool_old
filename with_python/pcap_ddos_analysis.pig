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
    tcp_ns:long,-- 19 Note: it was int in the packetpig
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

-- STORE pcap_mbps_pps INTO '$outputFolder/pcap_mbps_pps' USING PigStorage(',', '-schema');

-- ##########################################################
-- Generating the statistics of destination IP addresses (to find the target(s))
-- Output columns: (1) destination IP address and , (2) number of packets. SORTED decrescent by the number of packets 
-- ##########################################################
pkts_per_ip_dst = FOREACH (GROUP pcap BY ip_dst) GENERATE 
        group as ip_dst, 
        COUNT(pcap) as packets; -- considering that each line is a packet 

-- STORE (ORDER pkts_per_ip_dst BY packets DESC) INTO '$outputFolder/pcap_pkts_per_ip_dst' USING PigStorage(',', '-schema');

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

-- STORE (ORDER pcap_filter1_ipproto_with_desc BY occurrences DESC) INTO '$outputFolder/pcap_ip_proto' USING PigStorage(',', '-schema');

-- ##########################################################
-- Filtering the pcap_filter1 based on the IP protocol that had most of the traffic (top 1)
-- Output columns: the same 33 columns as in the original pcap
-- ##########################################################
top1_ip_proto = LIMIT (ORDER pcap_filter1_ipproto BY occurrences DESC) 1;
pcap_filter2 = FILTER pcap_filter1 BY (ip_proto == top1_ip_proto.ip_proto);

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
    udp_src_port as src_port,
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

-- STORE (ORDER pcap_filter2_sport_with_desc BY packets DESC) INTO '$outputFolder/pcap_filter2_sport' USING PigStorage(',', '-schema');

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
    udp_dst_port as dst_port,
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

-- STORE (ORDER pcap_filter2_dport_with_desc BY packets DESC) INTO '$outputFolder/pcap_filter2_dport' USING PigStorage(',', '-schema');

-- ##########################################################
-- Generating the time series of the filtered pcap file.
-- Output columns:(1) timestamp, (2) data rate [Mb/s], and (3) packet rate [packets/s]
-- ##########################################################
pcap_filter2_mbps_pps = FOREACH (GROUP pcap_filter2 BY (ts / $binsize * $binsize)) GENERATE 
        group AS timestamp, 
        (float)(SUM(pcap_filter2.ip_total_length))*8/1000000 AS mbits_per_bin,
        COUNT(pcap_filter2) AS pkts_per_bin;

-- STORE pcap_filter2_mbps_pps INTO '$outputFolder/pcap_filter2_mbps_pps' USING PigStorage(',', '-schema');

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

-- STORE pcap_filter2_stats INTO '$outputFolder/pcap_filter2_stats' USING PigStorage(',', '-schema');

-- ##########################################################
-- Generating the number of unique source IP address
-- Output columns: (1) number of unique source IP address
-- ##########################################################
pcap_filter2_uniq_sips = FOREACH (GROUP pcap_filter2 ALL){ 
        uniq_ips = DISTINCT pcap_filter2.ip_src; 
        GENERATE COUNT(uniq_ips);
};

-- ##########################################################
-- Generating the statistics for each source IP address
-- Output columns: (1) source IP address, (2) the total number of packets, (3) packets marketed as more fragments
-- ##########################################################
pcap_filter2_sip_statistics = FOREACH (GROUP pcap_filter2 BY ip_src) {
    total_packets = COUNT(pcap_filter2);
    fragmented_packets = FILTER pcap_filter2 BY (ip_more_fragments > 0);
    packets_fragment_marked = COUNT(fragmented_packets);
    distinct_udp_sport = DISTINCT pcap_filter2.udp_sport;
    distinct_tcp_sport = DISTINCT pcap_filter2.tcp_sport;

    GENERATE 
        group AS src_ip, 
        --
        total_packets as total_packets,
        packets_fragment_marked as packets_fragment_marked,
        --
        -- distinct_udp_sport AS distinct_udp_sport,
        -- distinct_tcp_sport AS distinct_tcp_sport,
        COUNT(distinct_udp_sport) AS num_distinct_udp_sport,
        COUNT(distinct_tcp_sport) AS num_distinct_tcp_sport,
        --
        AVG(pcap_filter2.ip_total_length) AS pkt_length_avg,
        FLATTEN(MEDIAN(pcap_filter2.ip_total_length)) AS pkt_length_median,
        MIN(pcap_filter2.ip_total_length) AS pkt_length_min,
        MAX(pcap_filter2.ip_total_length) AS pkt_length_max,
        SQRT(VARIANCE(pcap_filter2.ip_total_length)) AS pkt_length_std_dev,
        --
        AVG(pcap_filter2.ip_ttl) AS ttl_avg,
        MIN(pcap_filter2.ip_ttl) AS ttl_min,
        MAX(pcap_filter2.ip_ttl) AS ttl_max,
        SQRT(VARIANCE(pcap_filter2.ip_ttl)) AS ttl_std_dev,
        --
        SUM(pcap_filter2.tcp_cwr) AS tcp_flag_cwr,
        SUM(pcap_filter2.tcp_ece) AS tcp_flag_ece,
        SUM(pcap_filter2.tcp_urg) AS tcp_flag_urg,
        SUM(pcap_filter2.tcp_ack) AS tcp_flag_ack,
        SUM(pcap_filter2.tcp_psh) AS tcp_flag_psh,
        SUM(pcap_filter2.tcp_rst) AS tcp_flag_rst,
        SUM(pcap_filter2.tcp_syn) AS tcp_flag_syn,
        SUM(pcap_filter2.tcp_fin) AS tcp_flag_fin;

};
DUMP pcap_filter2_sip_statistics;

-- STORE (ORDER pcap_filter2_sip_statistics BY total_packets DESC) INTO '$outputFolder/pcap_filter2_sip_statistics' USING PigStorage(',', '-schema');

-- -- =========================================================
-- -- GENERATE (1) SOURCE IP (2) MBPS AVG (3) PPS AVG
-- -- =========================================================
-- pcap_filter2_sip_group = FOREACH (GROUP pcap_filter2 BY (ip_src, (ts / $binsize * $binsize))) GENERATE 
--         FLATTEN(group) AS (src_ip,bin),
--         (float)(SUM(pcap_filter2.ip_total_length))*8/1000000 AS mbits_per_bin,
--         COUNT(pcap_filter2) AS pkts_per_bin;

-- pcap_filter2_sip_bps_pps_avg = FOREACH (GROUP pcap_filter2_sip_group BY src_ip) GENERATE 
--         group AS src_ip,
--         AVG(pcap_filter2_sip_group.mbits_per_bin) AS mbits_per_bin_avg,
--         AVG(pcap_filter2_sip_group.pkts_per_bin) AS pkts_per_bin_avg;

-- STORE (ORDER pcap_filter2_sip_bps_pps_avg BY pkts_per_bin_avg DESC) INTO '$outputFolder/pcap_filter2_sip_bps_pps_avg' USING PigStorage(',', '-schema');


-- -- -- ##########################################################
-- -- -- IF REFLECTION ATTACK
-- -- -- ##########################################################
-- -- -- =========================================================
-- -- -- Calculate the spoofers_total_pps
-- -- -- =========================================================
-- -- -- =========================================================
-- -- -- spoofer_total_pps = amplifiers_total_resps
-- -- -- =========================================================
-- -- -- =========================================================
-- -- -- Calculate the spoofer_total_bps
-- -- -- =========================================================
-- -- -- =========================================================
-- -- -- spoofer_total_bps = amplifiers_total_resps * K
-- -- -- =========================================================

-- -- -- ##########################################################
-- -- -- NOTES:
-- -- -- ##########################################################
-- -- -- In the end of everything -- STORE 1 attack_summary and 1 attack_sip_summary (table) and move the pcap file out of hdfs

-- -- -- ##########################################################
-- -- -- CHALLENGE:
-- -- -- ##########################################################
-- -- -- -- STORE in AVRO!!!! AND PARQET



-- -- =========================================================
-- -- GENERATING CSVs FROM THE PIG OUTPUT
-- -- =========================================================
-- sh additional_data/preparing_csv.sh;
-- sh cp additional_data/DataAnalysis.html $outputFolder/index.html
-- sh cp additional_data/jquery.csv-0.71.js $outputFolder/

-- -- -- -- =========================================================
-- -- -- -- TRANSFERING THE RESULTS TO A APACHE SERVER
-- -- -- -- =========================================================
-- -- sh mv $outputFolder /Applications/MAMP/htdocs/
-- -- sh open http://localhost:8887/TrafficAnalysis_$filePcap

-- sh cd $outputFolder
-- sh python -m SimpleHTTPServer 
-- sh open http://localhost:8000/output/TrafficAnalysis_$filePcap