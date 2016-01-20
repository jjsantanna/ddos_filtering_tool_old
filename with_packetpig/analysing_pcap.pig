%DEFAULT includepath pig/include.pig
RUN $includepath;
register lib/datafu.jar
DEFINE MEDIAN datafu.pig.stats.StreamingMedian();
DEFINE VARIANCE datafu.pig.stats.VAR();

-- Parameters
-- NOTE: all values are per bin size, not per second
%DEFAULT binsize 1 
/*%DEFAULT binsize 60 --1min*/

-- =========================================================
-- PREPARING THE OUTPUT DIRECTORY
-- =========================================================
%DECLARE filePcap `basename $pcap`;
%DEFAULT outputFolder 'output/TrafficAnalysis_$filePcap';

-- =========================================================
-- Loading the full_traffic
-- =========================================================
full_traffic = load '$pcap' using com.packetloop.packetpig.loaders.pcap.packet.PacketLoader() AS (
    ts, --1
    ip_version:int, --2
    ip_header_length:int, --3
    ip_tos:int, --4
    ip_total_length:int, --5
    ip_id:int, --6
    ip_flags:int, --7
    ip_frag_offset:int, --8
    ip_ttl:int, --9
    ip_proto:int, --10
    ip_checksum:int, --11
    ip_src:chararray,--12
    ip_dst:chararray, --13
    tcp_sport:int, --14
    tcp_dport:int, --15
    tcp_seq_id:long, --16
    tcp_ack_id:long, --17
    tcp_offset:int, --18
    tcp_ns:int, --19
    tcp_cwr:int, --20
    tcp_ece:int, --21
    tcp_urg:int, --22
    tcp_ack:int, --23
    tcp_psh:int, --24
    tcp_rst:int, --25
    tcp_syn:int, --26
    tcp_fin:int, --27
    tcp_window:int,--28
    tcp_len:int, --29
    udp_sport:int, --30
    udp_dport:int, --31
    udp_len:int, --32
    udp_checksum:chararray --33
);

-- ##########################################################
-- GENERATING FULL TRAFFIC TIME SERIES
-- ##########################################################
-- =========================================================
-- TIMESERIES FULL TRAFFIC: (1) TIMESTAMP, (2) MB/S, (3)PP/S
-- =========================================================
full_traffic_bps_pps = FOREACH (GROUP full_traffic BY (ts / $binsize * $binsize)) GENERATE 
        group as timestamp, 
        (float)(SUM(full_traffic.ip_total_length))*8/1000000 as mbits_per_bin,
        COUNT(full_traffic) as pkts_per_bin;

STORE full_traffic_bps_pps INTO '$outputFolder/output_pig/full_traffic_bps_pps' USING PigStorage(',', '-schema');

-- ##########################################################
-- FILTER I: BASED ON THE TOP1 DESTINATION IP ADDRESS
-- ##########################################################
-- =========================================================
-- GENERATING (1) DESTINATION IP, (2) OCCURRENCES
-- =========================================================
pkts_per_ip_dst = FOREACH (GROUP full_traffic BY ip_dst) GENERATE 
        group as ip_dst, 
        COUNT(full_traffic) as packets;

STORE (ORDER pkts_per_ip_dst BY packets DESC) INTO '$outputFolder/output_pig/full_traffic_pkts_per_ip_dst' USING PigStorage(',', '-schema');

-- =========================================================
-- GENERATE (1) IP PROTOCOL, (2) OCCURRENCES
-- =========================================================
-- GENERATING: IP_PROTO_NUMBER, OCCURRENCES
top1_ip_dst = LIMIT (ORDER pkts_per_ip_dst BY packets DESC) 1;
full_traffic_filter1 = FILTER full_traffic BY (ip_dst == top1_ip_dst.ip_dst);

full_traffic_group_ipproto = FOREACH (GROUP full_traffic_filter1 BY ip_proto)GENERATE 
        group as ip_proto, 
        COUNT(full_traffic_filter1) as occurrences;

-- LOADING THE DESCRIPTION OF EACH PROTOCOL NUMBER
ip_proto_num_desc = LOAD 'data/list_ipprotocol_number_desc.txt' USING PigStorage(',') AS (
        ip_proto_number:int, 
        ip_proto_dst:chararray);

-- JOING THE IP PROTOCOL ANALYSIS WITH THE IP PROTOCOL DESCRIPTION LIST
joined_full_traffic_ip_proto_desc = FOREACH( JOIN full_traffic_group_ipproto BY ip_proto LEFT, ip_proto_num_desc BY ip_proto_number) GENERATE 
        ip_proto_dst as ip_proto, 
        occurrences as occurrences; 

STORE (ORDER joined_full_traffic_ip_proto_desc BY occurrences DESC) INTO '$outputFolder/output_pig/full_traffic_ip_proto' USING PigStorage(',', '-schema');

-- ##########################################################
-- FILTER II: BASED ON IP PROTOCOL
-- ##########################################################
-- =========================================================
-- FILTER THE ATTACK TRAFFIC ON TOP IP PROTOCOL 
-- =========================================================
top1_ip_proto = LIMIT (ORDER full_traffic_group_ipproto BY occurrences DESC) 1;
full_traffic_filter2 = FILTER full_traffic_filter1 BY (ip_proto == top1_ip_proto.ip_proto);

-- ##########################################################
-- PORT NUMBER ANALYSIS
-- ##########################################################
-- ========================================================= 
-- GENERATE (1) SOURCE PORT (2) PORT Description (3) COUNT TCP PACKETS (4) COUNT UDP PACKETS (5) TOTAL PACKETS
-- =========================================================
pkt_udp_port= FILTER full_traffic_filter2 BY udp_sport > 0;
total_pkt_udp_sport = FOREACH (GROUP pkt_udp_port BY udp_sport) GENERATE 
        group as udp_src_port, 
        COUNT(pkt_udp_port) as udp_packets;

pkt_tcp_port= FILTER full_traffic_filter2 BY tcp_sport > 0;
total_pkt_tcp_sport = FOREACH (GROUP pkt_tcp_port BY tcp_sport) GENERATE 
        group as tcp_src_port, 
        COUNT(pkt_tcp_port) as tcp_packets;

group_sport= FOREACH (JOIN total_pkt_udp_sport by udp_src_port FULL, total_pkt_tcp_sport BY tcp_src_port) GENERATE 
    udp_src_port as src_port,
    (udp_packets is null ? 0 : udp_packets) as udp_packets,
    (tcp_packets is null ? 0 : tcp_packets) as tcp_packets,
    ((udp_packets is null ? 0 : udp_packets) + (tcp_packets is null ? 0 : tcp_packets)) as packets;

port_names = LOAD 'data/port_names.txt' USING PigStorage(',') AS (
        port_number:int, 
        port_desc:chararray);

joined_sport_statistics = FOREACH( JOIN group_sport BY src_port LEFT, port_names BY port_number) GENERATE 
        src_port as src_port, 
        (port_desc is null ? 'unknown' : port_desc) as port_desc,
        udp_packets as udp_packets,
        tcp_packets as tcp_packets,
        packets as packets;

STORE (ORDER joined_sport_statistics BY packets DESC) INTO '$outputFolder/output_pig/full_traffic_filter2_sport' USING PigStorage(',', '-schema');

-- ========================================================= 
-- GENERATE (1) DESTINATION PORT (2) PORT DESCRIPTION (3) COUNT TCP PACKETS (4) COUNT UDP PACKETS (5) TOTAL PACKETS
-- =========================================================
pkt_udp_port= FILTER full_traffic_filter2 BY udp_dport > 0;
total_pkt_udp_dport = FOREACH (GROUP pkt_udp_port BY udp_dport) GENERATE 
        group as udp_dst_port, 
        COUNT(pkt_udp_port) as udp_packets;

pkt_tcp_port= FILTER full_traffic_filter2 BY tcp_dport > 0;
total_pkt_tcp_dport = FOREACH (GROUP pkt_tcp_port BY tcp_dport) GENERATE 
        group as tcp_dst_port, 
        COUNT(pkt_tcp_port) as tcp_packets;

group_dport= FOREACH (JOIN total_pkt_udp_dport by udp_dst_port FULL, total_pkt_tcp_dport BY tcp_dst_port) GENERATE 
    udp_dst_port as dst_port,
    (udp_packets is null ? 0 : udp_packets) as udp_packets,
    (tcp_packets is null ? 0 : tcp_packets) as tcp_packets,
    ((udp_packets is null ? 0 : udp_packets) + (tcp_packets is null ? 0 : tcp_packets)) as packets;

joined_dport_statistics = FOREACH( JOIN group_dport BY dst_port LEFT, port_names BY port_number) GENERATE 
        dst_port as dst_port, 
        (port_desc is null ? 'unknown' : port_desc) as port_desc,        
        udp_packets as udp_packets,
        tcp_packets as tcp_packets,
        packets as packets;

STORE (ORDER joined_dport_statistics BY packets DESC) INTO '$outputFolder/output_pig/full_traffic_filter2_dport' USING PigStorage(',', '-schema');


-- ##########################################################
-- FILTER III: PAYLOAD SIMILARITY
-- ##########################################################
-- ##########################################################
--      TO-DO SOON .... =D
-- ##########################################################
-- ##########################################################

-- ##########################################################
-- ATTACK TRAFFIC TIME SERIES
-- ##########################################################
-- =========================================================
-- TIMESERIES FULL TRAFFIC: (1) TIMESTAMP, (2) MB/S, (3)PP/S, (4) AVG PCKT SIZE PER SECOND, (5) MEDIAN PCKT SIZE PER SECOND
-- =========================================================
full_traffic_filter2_bps_pps = FOREACH (GROUP full_traffic_filter2 BY (ts / $binsize * $binsize)) GENERATE 
        group AS timestamp, 
        (float)(SUM(full_traffic_filter2.ip_total_length))*8/1000000 AS mbits_per_bin,
        COUNT(full_traffic_filter2) AS pkts_per_bin;

STORE full_traffic_filter2_bps_pps INTO '$outputFolder/output_pig/full_traffic_filter2_bps_pps' USING PigStorage(',', '-schema');

-- =========================================================
-- STATISTICS ATTACK TRAFFIC: (1) AVG MBPS (2) MEDIAN MBPS (3) STD_DEV MBPS (4) AVG PPS (5) MEDIAN PPS (6) STD_DEV PPS
-- =========================================================
full_traffic_filter2_stats = FOREACH (GROUP full_traffic_filter2_bps_pps ALL) GENERATE 
        AVG(full_traffic_filter2_bps_pps.mbits_per_bin) AS avg_mbps_full_traffic_filter2,
        FLATTEN(MEDIAN(full_traffic_filter2_bps_pps.mbits_per_bin)) AS median_mbps_full_traffic_filter2,
        SQRT(VARIANCE(full_traffic_filter2_bps_pps.mbits_per_bin)) AS std_dev_mbps_full_traffic_filter2,
        AVG(full_traffic_filter2_bps_pps.pkts_per_bin) AS avg_pps_full_traffic_filter2,
        FLATTEN(MEDIAN(full_traffic_filter2_bps_pps.pkts_per_bin)) AS median_pps_full_traffic_filter2,
        SQRT(VARIANCE(full_traffic_filter2_bps_pps.pkts_per_bin)) AS std_pps_dev_full_traffic_filter2;

STORE full_traffic_filter2_stats INTO '$outputFolder/output_pig/full_traffic_filter2_stats' USING PigStorage(',', '-schema');

-- ##########################################################
-- SOURCE IP ANALYSIS
-- ##########################################################
-- =========================================================
-- GENERATE (1) SOURCE IP ADDRESS (2) TOTAL NUMBER OF SENT PACKETS (3) NUMBER OF PACKETS MARQUED WITH FOLLOW-UP FRAGMENT (4) NUMBER OF PACKETS NON MARQUED WITH FOLLOW-UP FRAGMENT (5) DISTINCT UDP SOURCE PORTS (6,7,8) AVERAGE, MEDIAN AND STD_DEV OF PACKET LENGTH (9,10) AVERAGE AND STD_DEV TTL ***SORTED BY NUMBER OF PACKETS.
-- =========================================================
uniq_src_ips = FOREACH (GROUP full_traffic_filter2 ALL){ 
        uniq_ips = DISTINCT full_traffic_filter2.ip_src; 
        GENERATE COUNT(uniq_ips);
};

full_traffic_filter2_sip_statistics = FOREACH (GROUP full_traffic_filter2 BY ip_src) {
    total_packets = COUNT(full_traffic_filter2);

    fragmented_packets = FILTER full_traffic_filter2 BY (ip_frag_offset > 0);
    packets_fragment_marked = COUNT(fragmented_packets);

    distinct_udp_sport = DISTINCT full_traffic_filter2.udp_sport;

    GENERATE 
        group AS src_ip, 
        --
        total_packets as total_packets,
        packets_fragment_marked as packets_fragment_marked,
        (total_packets - packets_fragment_marked) AS packets_non_fragment_marked,
        --
        -- distinct_udp_sport AS distinct_udp_sport,
        COUNT(distinct_udp_sport) AS num_distinct_udp_sport,
        --
        AVG(full_traffic_filter2.ip_total_length) AS pkt_length_avg,
        FLATTEN(MEDIAN(full_traffic_filter2.ip_total_length)) AS pkt_length_median,
        MIN(full_traffic_filter2.ip_total_length) AS pkt_length_min,
        MAX(full_traffic_filter2.ip_total_length) AS pkt_length_max,
        SQRT(VARIANCE(full_traffic_filter2.ip_total_length)) AS pkt_length_std_dev,
        --
        AVG(full_traffic_filter2.ip_ttl) AS ttl_avg,
        MIN(full_traffic_filter2.ip_ttl) AS ttl_min,
        MAX(full_traffic_filter2.ip_ttl) AS ttl_max,
        SQRT(VARIANCE(full_traffic_filter2.ip_ttl)) AS ttl_std_dev;
}

STORE (ORDER full_traffic_filter2_sip_statistics BY total_packets DESC) INTO '$outputFolder/full_traffic_filter2_sip_statistics' USING PigStorage(',', '-schema');

-- =========================================================
-- GENERATE (1) SOURCE IP (2) MBPS AVG (3) PPS AVG
-- =========================================================
full_traffic_filter2_sip_group = FOREACH (GROUP full_traffic_filter2 BY (ip_src, (ts / $binsize * $binsize))) GENERATE 
        FLATTEN(group) AS (src_ip,bin),
        (float)(SUM(full_traffic_filter2.ip_total_length))*8/1000000 AS mbits_per_bin,
        COUNT(full_traffic_filter2) AS pkts_per_bin;

full_traffic_filter2_sip_bps_pps_avg = FOREACH (GROUP full_traffic_filter2_sip_group BY src_ip) GENERATE 
        group AS src_ip,
        AVG(full_traffic_filter2_sip_group.mbits_per_bin) AS mbits_per_bin_avg,
        AVG(full_traffic_filter2_sip_group.pkts_per_bin) AS pkts_per_bin_avg;

STORE (ORDER full_traffic_filter2_sip_bps_pps_avg BY pkts_per_bin_avg DESC) INTO '$outputFolder/full_traffic_filter2_sip_bps_pps_avg' USING PigStorage(',', '-schema');


-- -- ##########################################################
-- -- IF REFLECTION ATTACK
-- -- ##########################################################
-- -- =========================================================
-- -- Calculate the spoofers_total_pps
-- -- =========================================================
-- -- =========================================================
-- -- spoofer_total_pps = amplifiers_total_resps
-- -- =========================================================
-- -- =========================================================
-- -- Calculate the spoofer_total_bps
-- -- =========================================================
-- -- =========================================================
-- -- spoofer_total_bps = amplifiers_total_resps * K
-- -- =========================================================

-- -- ##########################################################
-- -- NOTES:
-- -- ##########################################################
-- -- In the end of everything -- STORE 1 attack_summary and 1 attack_sip_summary (table) and move the pcap file out of hdfs

-- -- ##########################################################
-- -- CHALLENGE:
-- -- ##########################################################
-- -- -- STORE in AVRO!!!! AND PARQET



-- =========================================================
-- GENERATING CSVs FROM THE PIG OUTPUT
-- =========================================================
sh output/preparing_csv.sh;
sh cp output/DataAnalysis.html $outputFolder/index.html
sh cp output/jquery.csv-0.71.js $outputFolder/

-- -- =========================================================
-- -- TRANSFERING THE RESULTS TO A APACHE SERVER
-- -- =========================================================
sh mv $outputFolder /Applications/MAMP/htdocs/
sh open http://localhost:8888/TrafficAnalysis_$filePcap

-- -- sh cd $outputFolder
-- -- sh python -m SimpleHTTPServer
-- -- sh open http://localhost:8000/TrafficAnalysis_$filePcap