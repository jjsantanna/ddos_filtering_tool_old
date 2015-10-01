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
-- Filter by TCP and UDP
-- =========================================================
/*full_traffic_tcp = FILTER full_traffic BY ip_proto == 6;*/
/*full_traffic_udp = FILTER full_traffic BY ip_proto == 17;*/

-- =========================================================
-- Using full_traffic generate timeseries [bps]
-- =========================================================
/*full_traffic_grouped = GROUP full_traffic BY (ts / $binsize * $binsize);*/
/*full_traffic_bps = FOREACH full_traffic_grouped GENERATE group, SUM(full_traffic.ip_total_length);*/
/*STORE full_traffic_bps INTO 'out/full_traffic_bps' USING PigStorage(',');*/

-- =========================================================
-- Using full_traffic generate timeseries [pps]
-- =========================================================

/*full_traffic_grouped = GROUP full_traffic BY (ts / $binsize * $binsize);*/
/*full_traffic_pps = FOREACH full_traffic_grouped GENERATE group, COUNT(full_traffic);*/
/*STORE full_traffic_pps INTO 'out/full_traffic_pps' USING PigStorage(',');*/

-- =========================================================
-- Using full_traffic, group by dIP and generate the total_pkt
-- =========================================================

group_ip_dst = GROUP full_traffic BY ip_dst;
total_ip_dst = FOREACH group_ip_dst GENERATE group as group_ip_dst, COUNT(full_traffic) as pkts;

-- ##########################################################
-- OVERALL ATTACK TRAFFIC ANALYSIS
-- ##########################################################

-- =========================================================
-- Filter full_traffic based on the dIP with highest total_pkt (store in attack_traffic)
-- =========================================================

top1_total_ip_dst = LIMIT (ORDER total_ip_dst BY pkts DESC) 1; --get top 1 from ordered packets per destination IP (maximum value)
attack_traffic = FILTER full_traffic BY ip_dst == top1_total_ip_dst.group_ip_dst;

-- =========================================================
-- Generate independent tcp and upd subsets
-- =========================================================

attack_traffic_tcp = FILTER full_traffic BY ip_proto == 6;
attack_traffic_udp = FILTER full_traffic BY ip_proto == 17;

-- =========================================================
-- Using on attack_traffic generate Timeserise [bps]
-- =========================================================

attack_traffic_grouped = GROUP attack_traffic BY (ts / $binsize * $binsize);
attack_traffic_bps = FOREACH attack_traffic_grouped GENERATE group, SUM(attack_traffic.ip_total_length);
/*STORE attack_traffic_bps INTO 'out/attack_traffic_bps.json' USING JsonStorage();*/

-- =========================================================
-- Using attack_traffic_bps calculate attack_traffic_bps_avg
-- =========================================================

attack_traffic_bps_avg = FOREACH attack_traffic_grouped GENERATE AVG(attack_traffic.ip_total_length);
/*DUMP attack_traffic_bps_avg;*/

-- =========================================================
-- Using attack_traffic_bps calculate attack_traffic_bps_median
-- =========================================================

attack_traffic_bps_median = FOREACH attack_traffic_grouped GENERATE MEDIAN(attack_traffic.ip_total_length);
/*DUMP attack_traffic_bps_median;*/

-- =========================================================
-- Using attack_traffic_bps calculate attack_traffic_bps_std
-- =========================================================

attack_traffic_bps_std = FOREACH attack_traffic_grouped GENERATE SQRT(VARIANCE(attack_traffic.ip_total_length));
/*DUMP attack_traffic_bps_std;*/

-- =========================================================
-- Using on attack_traffic generate Timeserise [pps]
-- =========================================================

attack_traffic_pps = FOREACH attack_traffic_grouped GENERATE COUNT(attack_traffic) as bin_count;

-- =========================================================
-- Using attack_traffic_pps calculate attack_traffic_pps_avg
-- =========================================================

attack_traffic_pps_avg = FOREACH (GROUP attack_traffic_pps ALL) GENERATE AVG(attack_traffic_pps.bin_count);
/*DUMP attack_traffic_pps_avg;*/

-- =========================================================
-- Using attack_traffic_pps calculate attack_traffic_pps_median
-- =========================================================

attack_traffic_pps_median = FOREACH (GROUP attack_traffic_pps ALL) GENERATE MEDIAN(attack_traffic_pps.bin_count);
/*DUMP attack_traffic_pps_median;*/

-- =========================================================
-- Using attack_traffic_ps calculate attack_traffic_pps_std
-- =========================================================

attack_traffic_pps_avg = FOREACH (GROUP attack_traffic_pps ALL) GENERATE SQRT(VARIANCE(attack_traffic_pps.bin_count));
/*DUMP attack_traffic_pps_avg;*/


-- ##########################################################
-- ATTACK TRAFFIC PORT ANALYSIS
-- ##########################################################

-- ========================================================= 
-- Based on attack_traffic group by sport and generate the total_pkt_sport (this can define the type of attack part1, plot hist sport) 
-- =========================================================
/*attack_by_tcp_sport = GROUP attack_traffic BY tcp_sport;*/

/*attack_by_udp_sport = ;*/
total_pkt_udp_sport = FOREACH (GROUP attack_traffic_udp BY udp_sport) GENERATE group as sport, COUNT(attack_traffic_udp) as packet_count;
/*DUMP total_pkt_udp_sport;*/
sorted_total_pkt_udp_sport = ORDER total_pkt_udp_sport BY packet_count;

-- =========================================================
-- Based on attack_traffic group by dport and generate the total_pkt_dPort (this can define the type of attack part2, plot hist dport)
-- =========================================================

total_pkt_udp_dport = FOREACH (GROUP attack_traffic_udp BY udp_dport) GENERATE group as dport, COUNT(attack_traffic_udp) as packet_count;
/*DUMP total_pkt_udp_dport;*/

-- =========================================================
-- Based on total_pkt_sport count how many unique values exist (store in uniq_sport)
-- =========================================================

total_pkt_udp_sport_uniq = FOREACH (GROUP total_pkt_udp_sport ALL) GENERATE COUNT(total_pkt_udp_sport.sport);
/*DUMP total_pkt_udp_sport_uniq;*/

-- =========================================================
-- Based on total_pkt_dport count how many unique values exist (store in uniq_dport)
-- =========================================================

total_pkt_udp_dport_uniq = FOREACH (GROUP total_pkt_udp_dport ALL) GENERATE COUNT(total_pkt_udp_dport.dport);
/*DUMP total_pkt_udp_dport_uniq;*/

-- ##########################################################
-- ATTACK TRAFFIC IP ANALYSIS
-- ##########################################################

-- =========================================================
-- Using attack_traffic group by sIP (store in group_sip)
-- =========================================================

total_pkt_sip = FOREACH (GROUP attack_traffic BY ip_src) 
				GENERATE group as sip, COUNT(attack_traffic) as pkt_per_ip;
-- DUMP total_pkt_sip;

-- =========================================================
-- sip_pkt_ipfragmented
-- =========================================================
attack_frag = FILTER attack_traffic BY ip_frag_offset>0;
total_pkt_frag = FOREACH (GROUP attack_frag BY ip_src) 
				 GENERATE group, COUNT(attack_frag) as pkt_per_ip;
/*DUMP total_pkt_frag;*/

-- =========================================================
-- sip_pkt_sport_uniq_values
-- ========================================================= 

-- There must be a simpler way!!!

sip_sport_attack = FOREACH (GROUP attack_traffic BY (ip_src, udp_sport))
				   GENERATE FLATTEN(group) as (sip, sport), COUNT(attack_traffic) as count;

group_sip_sport_attack = FOREACH (GROUP sip_sport_attack BY sip){
						 sport_count = FOREACH sip_sport_attack GENERATE sport, count;
						 GENERATE group as sip, sport_count;
}
-- DUMP group_sip_sport_attack;

-- =========================================================
-- sip_pkt_top1_sport - method 1
-- =========================================================

-- There must be a simpler way!!!

sip_top_sport = FOREACH group_sip_sport_attack{
	   ordered_sport_count = ORDER sport_count BY count DESC;
	   top_sport_count = LIMIT ordered_sport_count 1;		
	   GENERATE sip, FLATTEN(top_sport_count) as (sport, count);
}
/*DUMP sip_top_sport;*/

-- =========================================================
-- sip_pkt_top1_sport_percentage
-- =========================================================

sip_total_count_sport = FOREACH group_sip_sport_attack GENERATE sip, SUM(sport_count.count) as total;
/*X = JOIN A BY a1, B BY b1;*/
joined_top_count = JOIN sip_top_sport BY sip, sip_total_count_sport BY sip;
/*DESCRIBE joined_top_count;*/
sip_top_sport_percentage = FOREACH joined_top_count GENERATE sip_top_sport::sip, sport, ((float)count/(float)total * 100);
/*DUMP sip_top_sport_percentage;*/


-- =========================================================
-- sip_pkt_sport_uniq_values
-- =========================================================
-- =========================================================
-- sip_pkt_top1_dport
-- =========================================================
-- =========================================================
-- sip_pkt_top1_dport_percentage
-- =========================================================
-- =========================================================
-- sip_pkt_length_avg, 
-- =========================================================
-- =========================================================
-- sip_pkt_length_uniq_values,
-- =========================================================
-- =========================================================
-- sip_pkt_length_std, 
-- =========================================================
-- =========================================================
-- sip_pkt_ttl_avg
-- =========================================================
-- =========================================================
-- sip_pkt_ttl_uniq_values,
-- =========================================================
-- =========================================================
-- sip_pkt_ttl_std
-- =========================================================
-- =========================================================
-- sip_pps [timeseries]		
-- =========================================================
-- =========================================================
-- sip_pps_avg
-- =========================================================
-- =========================================================
-- sip_pps_median
-- =========================================================
-- =========================================================
-- sip_pps_uniq_values
-- =========================================================
-- =========================================================
-- sip_pps_std
-- =========================================================
-- =========================================================
-- sip_bps [timeseries]
-- =========================================================
-- =========================================================
-- sip_bps_avg
-- =========================================================
-- =========================================================
-- sip_bps_median
-- =========================================================
-- =========================================================
-- sip_bps_uniq_values
-- =========================================================
-- =========================================================
-- sip_bps_std
-- =========================================================
-- =========================================================
-- sip_payload_similarity*** (size? value?)
-- =========================================================

-- ##########################################################
-- IF REFLECTION ATTACK
-- ##########################################################
-- =========================================================
-- Calculate the spoofers_total_pps
-- =========================================================

-- =========================================================
-- Sum sip_pps_median/(sip_pkt_total/sip_pkt_ipfragmented) [store in amplifiers_total_resps: responses per second] BE CAREFUL WITH sip_pkt_ipfragmented=0
-- =========================================================

-- =========================================================
-- REMEMBER that in a DRDoS the num_responses = num_requests SO 
-- =========================================================

-- =========================================================
-- spoofer_total_pps = amplifiers_total_resps
-- =========================================================

-- =========================================================
-- Calculate the spoofer_total_bps
-- =========================================================

-- =========================================================
-- REMEMBER that req_pkt_length is constant (k)
-- =========================================================

-- =========================================================
-- spoofer_total_bps = amplifiers_total_resps * K
-- =========================================================

-- ##########################################################
-- NOTES:
-- ##########################################################
-- In the end of everything store 1 attack_summary and 1 attack_sip_summary (table) and move the pcap file out of hdfs

-- ##########################################################
-- CHALLENGE:
-- ##########################################################
-- Store in AVRO!!!! AND PARQET
