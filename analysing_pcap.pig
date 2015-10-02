%DEFAULT includepath pig/include.pig
RUN $includepath;
register lib/datafu.jar
DEFINE MEDIAN datafu.pig.stats.StreamingMedian();
DEFINE VARIANCE datafu.pig.stats.VAR();

-- Parameters
-- NOTE: all values are per bin size, not per second
%DEFAULT binsize 1 
/*%DEFAULT binsize 60 --1min*/

%DEFAULT out '/Applications/MAMP/htdocs/TrafficAnalysis/output_pig'
-- =========================================================
-- Loading the full_traffic
-- =========================================================
full_traffic = load '$pcap' using com.packetloop.packetpig.loaders.pcap.packet.PacketLoader() AS (
    ts,
    ip_version:int,
    ip_header_length:int,
    ip_tos:int,
    ip_total_length:int,
    ip_id:int,
    ip_flags:int,
    ip_frag_offset:int,
    ip_ttl:int,
    ip_proto:int,
    ip_checksum:int,
    ip_src:chararray,
    ip_dst:chararray,
    tcp_sport:int,
    tcp_dport:int,
    tcp_seq_id:long,
    tcp_ack_id:long,
    tcp_offset:int,
    tcp_ns:int,
    tcp_cwr:int,
    tcp_ece:int,
    tcp_urg:int,
    tcp_ack:int,
    tcp_psh:int,
    tcp_rst:int,
    tcp_syn:int,
    tcp_fin:int,
    tcp_window:int,
    tcp_len:int,
    udp_sport:int,
    udp_dport:int,
    udp_len:int,
    udp_checksum:chararray
);

-- =========================================================
-- GENERATE (1) IP PROTOCOL, (2) OCCURRENCES
-- =========================================================
-- GENERATING: IP_PROTO_NUMBER, OCCURRENCES
full_traffic_group_ipproto = FOREACH (GROUP full_traffic BY ip_proto) GENERATE 
        group as ip_proto, 
        COUNT(full_traffic) as occurrences;

-- LOADING THE DESCRIPTION OF EACH PROTOCOL NUMBER
ip_proto_num_desc = LOAD 'list_ipprotocol_number_desc.txt' USING PigStorage(',') AS (
        ip_proto_number:int, 
        ip_proto_dst:chararray);

-- JOING THE IP PROTOCOL ANALYSIS WITH THE IP PROTOCOL DESCRIPTION LIST
joined_full_traffic_ip_proto_desc = FOREACH( JOIN full_traffic_group_ipproto BY ip_proto, ip_proto_num_desc BY ip_proto_number) GENERATE 
        ip_proto_dst as ip_proto, 
        occurrences as occurrences; 

-- STORING THE OUTPUT
-- STORE joined_full_traffic_ip_proto_desc INTO '$out/full_traffic_ip_proto' USING PigStorage(',', '-schema');


-- =========================================================
-- TIMESERIES FULL TRAFFIC: (1) TIMESTAMP, (2) MB/S, (3)PP/S
-- =========================================================
full_traffic_bps_pps = FOREACH (GROUP full_traffic BY (ts / $binsize * $binsize)) GENERATE 
        group as timestamp, 
        (float)(SUM(full_traffic.ip_total_length))*8/1000000 as mbits_per_bin,
        COUNT(full_traffic) as pkts_per_bin;

-- STORING THE OUTPUT
-- STORE full_traffic_bps_pps INTO '$out/full_traffic_bps_pps' USING PigStorage(',', '-schema');

-- =========================================================
-- GENERATING (1) DESTINATION IP, (2) OCCURRENCES
-- =========================================================
pkts_per_ip_dst = FOREACH (GROUP full_traffic BY ip_dst) GENERATE 
        group as ip_dst, 
        COUNT(full_traffic) as packets;

-- STORING THE OUTPUT
-- STORE pkts_per_ip_dst INTO '$out/pkts_per_ip_dst' USING PigStorage(',', '-schema');

-- ##########################################################
-- PART II: ATTACK TRAFFIC ANALYSIS
-- ##########################################################

-- =========================================================
-- FILTER THE ATTACK TRAFFIC FROM THE FULL TRAFFIC (BASED ON TOP IP PROTOCOL AND DESTINATION IP ADDRESS)
-- =========================================================
top1_ip_proto = LIMIT (ORDER full_traffic_group_ipproto BY occurrences DESC) 1;
top1_ip_dst = LIMIT (ORDER pkts_per_ip_dst BY packets DESC) 1; 
attack_traffic = FILTER full_traffic BY (ip_proto == top1_ip_proto.ip_proto) AND (ip_dst == top1_ip_dst.ip_dst);

-- =========================================================
-- TIMESERIES FULL TRAFFIC: (1) TIMESTAMP, (2) MB/S, (3)PP/S, (4) AVG PCKT SIZE PER SECOND, (5) MEDIAN PCKT SIZE PER SECOND
-- =========================================================
attack_traffic_bps_pps = FOREACH (GROUP attack_traffic BY (ts / $binsize * $binsize)) GENERATE 
        group AS timestamp, 
        (float)(SUM(attack_traffic.ip_total_length))*8/1000000 AS mbits_per_bin,
        COUNT(attack_traffic) AS pkts_per_bin;
        -- (float)(AVG(attack_traffic.ip_total_length))*8/1000000 AS avg_mbits_per_bin,
        -- (float)(MEDIAN(attack_traffic.ip_total_length)) AS median_mbits_per_bin,
        -- (float)(SQRT(VARIANCE(attack_traffic.ip_total_length))) AS std_mbits_per_bin,

-- STORING THE OUTPUT
-- STORE attack_traffic_bps_pps INTO '$out/attack_traffic_bps_pps' USING PigStorage(',', '-schema');

-- =========================================================
-- STATISTICS ATTACK TRAFFIC: (1) AVG MBPS (2) MEDIAN MBPS (3) STD_DEV MBPS (4) AVG PPS (5) MEDIAN PPS (6) STD_DEV PPS
-- =========================================================
attack_traffic_stats = FOREACH (GROUP attack_traffic_bps_pps ALL) GENERATE 
        AVG(attack_traffic_bps_pps.mbits_per_bin) AS avg_mbps_attack_traffic,
        MEDIAN(attack_traffic_bps_pps.mbits_per_bin) AS median_mbps_attack_traffic,
        SQRT(VARIANCE(attack_traffic_bps_pps.mbits_per_bin)) AS std_dev_mbps_attack_traffic,
        AVG(attack_traffic_bps_pps.pkts_per_bin) AS avg_pps_attack_traffic,
        MEDIAN(attack_traffic_bps_pps.pkts_per_bin) AS median_pps_attack_traffic,
        SQRT(VARIANCE(attack_traffic_bps_pps.pkts_per_bin)) AS std_pps_dev_attack_traffic;

-- STORE attack_traffic_stats INTO '$out/attack_traffic_stats' USING PigStorage(',', '-schema');

-- ##########################################################
-- ATTACK TRAFFIC: PORT ANALYSIS
-- ##########################################################

-- ========================================================= 
-- GENERATE (1) SOURCE PORT (TCP and UDP) (2) PACKETS !!!! *******ATT WE NEED TO JOIN WITH TCP!!!! 
-- =========================================================
total_pkt_udp_sport = FOREACH (GROUP attack_traffic BY udp_sport) GENERATE 
        group as udp_src_port, 
        COUNT(attack_traffic) as packets;

-- STORE total_pkt_udp_sport INTO '$out/attack_traffic_pkts_per_udp_port' USING PigStorage(',', '-schema');

-- ========================================================= 
-- GENERATE (1) DESTINATION PORT (TCP and UDP) (2) PACKETS !!!! *******ATT WE NEED TO JOIN WITH TCP!!!! 
-- =========================================================
total_pkt_udp_dport = FOREACH (GROUP attack_traffic BY udp_dport) GENERATE 
        group as udp_dst_port, 
        COUNT(attack_traffic) as packets;

-- STORE total_pkt_udp_dport INTO '$out/attack_traffic_pkts_per_udp_dport' USING PigStorage(',', '-schema');

-- ##########################################################
-- ATTACK TRAFFIC: SOURCE IP ANALYSIS
-- ##########################################################

-- =========================================================
-- GENERATE (1) SOURCE IP ADDRESS (2) NUMBER OF SENT PACKETS (3) NUMBER OF PACKETS MARQUED WITH FOLLOW-UP FRAGMENT (4) DISTINCT UDP SOURCE PORTS (5,6,7) AVERAGE, MEDIAN AND STD_DEV OF PACKET LENGTH (8,9) AVERAGE AND STD_DEV TTL
-- =========================================================
attack_traffic_sip_statistics = FOREACH (GROUP attack_traffic BY ip_src) {
    fragmented_packets = FILTER attack_traffic BY (ip_frag_offset > 0);
    distinct_udp_sport = DISTINCT attack_traffic.udp_sport;

    GENERATE 
        group AS src_ip, 
        --
        COUNT(attack_traffic) AS packets,
        COUNT(fragmented_packets) AS packets_fraqment_marked,
        --
        distinct_udp_sport AS distinct_udp_sport,
        COUNT(distinct_udp_sport) AS num_distinct_udp_sport,
        --
        AVG(attack_traffic.ip_total_length) AS pkt_length_avg,
        MEDIAN(attack_traffic.ip_total_length) AS pkt_length_median,
        SQRT(VARIANCE(attack_traffic.ip_total_length)) AS pkt_length_std_dev,
        --
        AVG(attack_traffic.ip_ttl) AS ttl_avg,
        SQRT(VARIANCE(attack_traffic.ip_ttl)) AS ttl_std_dev;
}
STORE attack_traffic_sip_statistics INTO '$out/attack_traffic_sip_statistics' USING PigStorage(',', '-schema');



-- -- =========================================================
-- -- sip_pkt_top1_sport - method 1
-- -- =========================================================

-- -- There must be a simpler way!!!

-- sip_top_sport = FOREACH group_sip_sport_attack{
-- 	   ordered_sport_count = ORDER sport_count BY count DESC;
-- 	   top_sport_count = LIMIT ordered_sport_count 1;		
-- 	   GENERATE sip, FLATTEN(top_sport_count) as (sport, count);
-- }
-- /*DUMP sip_top_sport;*/

-- -- =========================================================
-- -- sip_pkt_top1_sport_percentage
-- -- =========================================================

-- sip_total_count_sport = FOREACH group_sip_sport_attack GENERATE sip, SUM(sport_count.count) as total;
-- /*X = JOIN A BY a1, B BY b1;*/
-- joined_top_count = JOIN sip_top_sport BY sip, sip_total_count_sport BY sip;
-- /*DESCRIBE joined_top_count;*/
-- sip_top_sport_percentage = FOREACH joined_top_count GENERATE sip_top_sport::sip, sport, ((float)count/(float)total * 100);
-- /*DUMP sip_top_sport_percentage;*/

-- -- =========================================================
-- -- sip_pkt_top1_dport
-- -- =========================================================
-- -- =========================================================
-- -- sip_pkt_top1_dport_percentage
-- -- =========================================================



-- -- =========================================================
-- -- sip_pps [timeseries]		
-- -- =========================================================
-- -- =========================================================
-- -- sip_pps_avg
-- -- =========================================================
-- -- =========================================================
-- -- sip_pps_median
-- -- =========================================================
-- -- =========================================================
-- -- sip_pps_uniq_values
-- -- =========================================================
-- -- =========================================================
-- -- sip_pps_std
-- -- =========================================================
-- -- =========================================================
-- -- sip_bps [timeseries]
-- -- =========================================================
-- -- =========================================================
-- -- sip_bps_avg
-- -- =========================================================
-- -- =========================================================
-- -- sip_bps_median
-- -- =========================================================
-- -- =========================================================
-- -- sip_bps_uniq_values
-- -- =========================================================
-- -- =========================================================
-- -- sip_bps_std
-- -- =========================================================
-- -- =========================================================
-- -- sip_payload_similarity*** (size? value?)
-- -- =========================================================

-- -- ##########################################################
-- -- IF REFLECTION ATTACK
-- -- ##########################################################
-- -- =========================================================
-- -- Calculate the spoofers_total_pps
-- -- =========================================================

-- -- =========================================================
-- -- Sum sip_pps_median/(sip_pkt_total/sip_pkt_ipfragmented) [store in amplifiers_total_resps: responses per second] BE CAREFUL WITH sip_pkt_ipfragmented=0
-- -- =========================================================

-- -- =========================================================
-- -- REMEMBER that in a DRDoS the num_responses = num_requests SO 
-- -- =========================================================

-- -- =========================================================
-- -- spoofer_total_pps = amplifiers_total_resps
-- -- =========================================================

-- -- =========================================================
-- -- Calculate the spoofer_total_bps
-- -- =========================================================

-- -- =========================================================
-- -- REMEMBER that req_pkt_length is constant (k)
-- -- =========================================================

-- -- =========================================================
-- -- spoofer_total_bps = amplifiers_total_resps * K
-- -- =========================================================

-- -- ##########################################################
-- -- NOTES:
-- -- ##########################################################
-- -- In the end of everything store 1 attack_summary and 1 attack_sip_summary (table) and move the pcap file out of hdfs

-- -- ##########################################################
-- -- CHALLENGE:
-- -- ##########################################################
-- -- Store in AVRO!!!! AND PARQET

-- -- -- =========================================================
-- -- -- FILTERING BY TCP and UDP
-- -- -- =========================================================
-- -- full_traffic_tcp = FILTER full_traffic BY ip_proto == 6;
-- -- full_traffic_udp = FILTER full_traffic BY ip_proto == 17;


-- -- =========================================================
-- -- Generate independent tcp and upd subsets
-- -- =========================================================

-- -- attack_traffic_tcp = FILTER full_traffic BY ip_proto == 6;
-- -- attack_traffic_udp = FILTER full_traffic BY ip_proto == 17;
