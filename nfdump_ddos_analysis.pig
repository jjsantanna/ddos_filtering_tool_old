register lib_and_extras/datafu.jar
DEFINE MEDIAN datafu.pig.stats.StreamingMedian();
DEFINE VARIANCE datafu.pig.stats.VAR();

Register lib_and_extras/myudfs.py using jython as myudfs;


%DEFAULT binsize 1 -- second

%DECLARE fileflow `basename $inputfile`;
%DEFAULT outputFolder 'output_example/TrafficAnalysis_$fileflow';


flowfile = LOAD '$inputfile' USING PigStorage(' ') AS (
	ts, --1 t-start
	ip_proto:chararray, --2 protocol PF_INET or PF_INET6 e.g., TCP or UDP
    ip_src:chararray, --3 sa: src address 
    ip_dst:chararray, --4 da: dst address 
    sport:int, --5 sp: src port
    dport:int, --6 dp: dst port      
	pkts:int, -- 7 input packets/bytes
	byts:int,  -- 8 input packets/bytes
	tcp_flg:chararray, -- 9 TCP Flags: 000001 FIN. 000010 SYN. 000100 RESET.	 001000 PUSH.010000 ACK. 100000 URGENT.	 e.g. 6 => SYN + RESET
	stos:int    -- 10 dst tos
	);

-- ##########################################################
-- Generating the time series of the raw flow file.
-- Output columns:(1) timestamp, (2) data rate [Mb/s], and (3) packet rate [packets/s]
-- ##########################################################
flow_mbps_pps = FOREACH (GROUP flowfile BY (ts / $binsize * $binsize)) GENERATE 
        group as timestamp, 
        (float)(SUM(flowfile.byts))*8/1000000 as mbits_per_second,
        (float)(SUM(flowfile.pkts)) as pkts_per_second;
       
-- STORE flow_mbps_pps INTO '$outputFolder/flow_mbps_pps' USING PigStorage(',', '-schema');

-- ##########################################################
-- Generating the statistics of destination IP addresses (to find the target(s))
-- Output columns: (1) destination IP address and , (2) number of packets. SORTED decrescent by the number of packets 
-- ##########################################################
pkts_per_ip_dst = FOREACH (GROUP flowfile BY ip_dst) GENERATE 
        group as ip_dst, 
        (float)(SUM(flowfile.pkts)) as packets; 

-- STORE (ORDER pkts_per_ip_dst BY packets DESC) INTO '$outputFolder/flow_pkts_per_ip_dst' USING PigStorage(',', '-schema');

-- ##########################################################
-- Filtering the entire flow file based on the destination IP address that most received packets (top1)
-- Output columns: the same 33 columns as in the original flow
-- ##########################################################
top1_ip_dst = LIMIT (ORDER pkts_per_ip_dst BY packets DESC) 1;
flow_filter1 = FILTER flowfile BY (ip_dst == top1_ip_dst.ip_dst);

-- ##########################################################
-- Generating the statistics about the IP protocols (e.g., ICMP, TCP, UDP)
-- Output columns: (1) ip protocol number, (2) total number of occurrences
-- ##########################################################
flow_filter1_ipproto = FOREACH (GROUP flow_filter1 BY ip_proto)GENERATE 
        group as ip_proto, 
        COUNT(flow_filter1) as occurrences;

-- STORE (ORDER flow_filter1_ipproto BY occurrences DESC) INTO '$outputFolder/flow_ip_proto' USING PigStorage(',', '-schema');

-- ##########################################################
-- Filtering the flow_filter1 based on the IP protocol that had most of the traffic (top 1)
-- Output columns: the same 33 columns as in the original flow
-- ##########################################################
top1_ip_proto = LIMIT (ORDER flow_filter1_ipproto BY occurrences DESC) 1;
flow_filter2 = FILTER flow_filter1 BY (ip_proto == top1_ip_proto.ip_proto);

-- ##########################################################
-- Generating list of src IP addresses involved in the attack
-- Output columns: 1) source IP
-- ##########################################################
flow_filter2_sip = FOREACH (GROUP flow_filter2 BY ip_src) GENERATE group;

-- STORE flow_filter2_sip INTO '$outputFolder/flow_filter2_sip' USING PigStorage(',');


-- ##########################################################
-- Getting the ASN for each source IP
-- ##########################################################

-- sh lib_and_extras/get_ans.sh '$outputFolder/flow_filter2_sip';
flow_filter2_sip_ans = LOAD '$outputFolder/flow_filter2_sip/filter2_sip_ans.txt' USING PigStorage(';') AS (
        asn:chararray,
        ip:chararray, 
        bgp_prefix:chararray, 
        country:chararray, 
        as_info:chararray
    );

-- ##########################################################
-- Grouping the source port number analysis of UDP and TCP
-- Output columns: (1) source port number, (2) occurrences over udp, (3) occurrences over tcp, (4) total number of packets 
-- ##########################################################
flow_filter2_sport= FOREACH (GROUP flow_filter2 BY sport)GENERATE 
    group as src_port,
    (float)(SUM(flow_filter2.pkts)) as packets;


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
flow_filter2_sport_with_desc = FOREACH( JOIN flow_filter2_sport BY src_port LEFT, portnumber_desc BY port_number) GENERATE 
        CONCAT((chararray)src_port,CONCAT(':',(chararray)(port_desc is null ? 'unknown' : port_desc))) as src_port, 
        packets as packets;

-- STORE (ORDER flow_filter2_sport_with_desc BY packets DESC) INTO '$outputFolder/flow_filter2_sport' USING PigStorage(',', '-schema');

-- ##########################################################
-- Grouping the source port number analysis of UDP and TCP
-- Output columns: (1) source port number, (2) occurrences over udp, (3) occurrences over tcp, (4) total number of packets 
-- ##########################################################
flow_filter2_dport= FOREACH (GROUP flow_filter2 BY dport)GENERATE 
    group as dst_port,
    (float)(SUM(flow_filter2.pkts)) as packets;

-- ##########################################################
-- Join the statistics of port number with the port description
-- Output columns: (1) ip protocol number, (2) ip protocol description
-- ##########################################################
flow_filter2_dport_with_desc = FOREACH( JOIN flow_filter2_dport BY dst_port LEFT, portnumber_desc BY port_number) GENERATE 
        CONCAT((chararray)dst_port,CONCAT(':',(chararray)(port_desc is null ? 'unknown' : port_desc))) as dst_port, 
        packets as packets;

-- STORE (ORDER flow_filter2_dport_with_desc BY packets DESC) INTO '$outputFolder/flow_filter2_dport' USING PigStorage(',', '-schema');

-- ##########################################################
-- Generating the statistics for each source IP address
-- Output columns: (1) source IP address, (2) the total number of packets, (3) packets marked as more fragments (4) packets NON marked as more fragments (5) num of distinct source ports (6) num of distinct destination ports (7,8,9,10,11) avg, min, max, median, and std of the packet lenght [bytes] (12,12,13,15) Avg, min, max, std of the TTL (16-23) number of occurrences of TCP flags
-- ##########################################################
flow_filter2_sip_stats = FOREACH (GROUP flow_filter2 BY ip_src) {
    total_packets = (float)(SUM(flow_filter2.pkts));
    distinct_sport = DISTINCT flow_filter2.sport;
    distinct_dport = DISTINCT flow_filter2.dport;
    distinct_flags = DISTINCT flow_filter2.tcp_flg;
    GENERATE 
        group AS src_ip, --1
        --
        total_packets as total_packets, --2
        myudfs.convertBagToStr(distinct_sport) AS distinct_sport, --3
        myudfs.convertBagToStr(distinct_dport) AS distinct_dport, --4
        COUNT(distinct_sport) AS tot_distinct_sport, --5
        COUNT(distinct_dport) AS tot_distinct_dport, --6
        --
        AVG(flow_filter2.byts) AS pkt_length_avg, --7
        MIN(flow_filter2.byts) AS pkt_length_min, --8
        MAX(flow_filter2.byts) AS pkt_length_max, --9
        FLATTEN(MEDIAN(flow_filter2.byts)) AS pkt_length_median, --10
        SQRT(VARIANCE(flow_filter2.byts)) AS pkt_length_std_dev, --11
        --
        distinct_flags as distinct_flags; --12
};

-- ##########################################################
-- Generating the timeseries (data and packet rate) of each source IP address (all together)
-- Output columns: (1) source IP address (2) timestamp (3) data rate [Mb/s] (4) packet rate [pckt/s]
-- ##########################################################
flow_filter2_sip_mbps_pps = FOREACH (GROUP flow_filter2 BY (ip_src, (ts / $binsize * $binsize))) GENERATE 
        FLATTEN(group) AS (src_ip,bin),
        (float)(SUM(flow_filter2.byts))*8/1000000 AS mbits_per_second,
        (float)(SUM(flow_filter2.pkts)) AS pkts_per_second;

-- STORE (ORDER flow_filter2_sip_mbps_pps BY bin) INTO '$outputFolder/flow_filter2_sip_mbps_pps' USING PigStorage(',', '-schema');

-- ##########################################################
-- Generating the statistics of each source IP address (all together)
-- Output columns: (1) source IP address (2) timestamp (3) data rate [Mb/s] (4) packet rate [pckt/s]
-- ##########################################################
flow_filter2_sip_mbps_pps_statistics = FOREACH (GROUP flow_filter2_sip_mbps_pps BY src_ip) GENERATE 
        group AS src_ip,
        AVG(flow_filter2_sip_mbps_pps.mbits_per_second) AS mbits_per_second_avg,
        AVG(flow_filter2_sip_mbps_pps.pkts_per_second) AS pkts_per_second_avg;

-- ##########################################################
-- Join the general statistics of source IPs with their data and packet rate statistics
-- Output columns: 
-- ##########################################################
flow_filter2_sip_stats_joined = FOREACH (JOIN flow_filter2_sip_stats BY src_ip LEFT, flow_filter2_sip_mbps_pps_statistics BY src_ip) GENERATE 
        flow_filter2_sip_stats::src_ip AS src_ip, --1
        total_packets AS total_packets, --2
        distinct_sport AS distinct_sport, --3
        distinct_dport AS distinct_dport, --4
        tot_distinct_sport AS tot_distinct_sport, --5
        tot_distinct_dport AS tot_distinct_dport, --6
        --
        pkt_length_avg AS pkt_length_avg, --7
        pkt_length_min AS pkt_length_min, --8
        pkt_length_max AS pkt_length_max, --9
        pkt_length_median AS pkt_length_median, --10
        pkt_length_std_dev AS pkt_length_std_dev, --11
		distinct_flags as distinct_flags,--12
		--
        mbits_per_second_avg AS mbits_per_second_avg, --13
        pkts_per_second_avg AS pkts_per_second_avg; --14


-- ##########################################################
-- Joining the statistics of source IPs with their ASN
-- ##########################################################
flow_filter2_sip_stats_asn = FOREACH (JOIN flow_filter2_sip_stats_joined BY src_ip LEFT, flow_filter2_sip_ans BY ip) GENERATE 
        src_ip AS src_ip, --1
        total_packets AS total_packets, --2
        distinct_sport AS distinct_sport, --3
        distinct_dport AS distinct_dport, --4
        tot_distinct_sport AS tot_distinct_sport, --5
        tot_distinct_dport AS tot_distinct_dport, --6
        --
        pkt_length_avg AS pkt_length_avg, --7
        pkt_length_min AS pkt_length_min, --8
        pkt_length_max AS pkt_length_max, --9
        pkt_length_median AS pkt_length_median, --10
        pkt_length_std_dev AS pkt_length_std_dev, --11
		distinct_flags as distinct_flags,--12
		--
        mbits_per_second_avg AS mbits_per_second_avg, --13
        pkts_per_second_avg AS pkts_per_second_avg, --14
        --
        asn AS asn, --15
        bgp_prefix AS bgp_prefix, --16
        country AS country, --17
        as_info AS as_info; --18

STORE (ORDER flow_filter2_sip_stats_asn BY total_packets DESC) INTO '$outputFolder/flow_filter2_sip_stats' USING PigStorage(',', '-schema');

-- ##########################################################
-- Generating statistics about the ASes
-- ##########################################################
flow_filter2_country_stats = FOREACH (GROUP flow_filter2_sip_stats_asn BY country) GENERATE 
    (group is null ? 'NONE' : group) AS country,
    COUNT(flow_filter2_sip_stats_asn.src_ip) AS sips;

STORE (ORDER flow_filter2_country_stats BY sips DESC) INTO '$outputFolder/flow_filter2_country_stats' USING PigStorage(',', '-schema');;

-- ##########################################################
-- Generating statistics about BGP prefixes
-- ##########################################################
flow_filter2_bgp_stats = FOREACH (GROUP flow_filter2_sip_stats_asn BY bgp_prefix) GENERATE 
    (group is null ? 'NONE' : group) AS bgp_prefix,
    COUNT(flow_filter2_sip_stats_asn.src_ip) AS sips;

STORE (ORDER flow_filter2_bgp_stats BY sips DESC) INTO '$outputFolder/flow_filter2_bgp_stats' USING PigStorage(',', '-schema');;

-- ##########################################################
-- Generating statistics about BGP prefixes
-- ##########################################################
flow_filter2_asn_stats = FOREACH (GROUP flow_filter2_sip_stats_asn BY asn) GENERATE 
    (group is null ? 'NONE' : group) AS asn,
    COUNT(flow_filter2_sip_stats_asn.src_ip) AS sips;

STORE (ORDER flow_filter2_asn_stats BY sips DESC) INTO '$outputFolder/flow_filter2_asn_stats' USING PigStorage(',', '-schema');;

-- ##########################################################
-- Generating CSV files of the outputs. By default PIG outputs 2 files in a folder: "_SUCESS" and "part-r-00000" (results) AND among others HIDDEN files ".pig_header" and ".pig_schema". Then we wrote a code "preparing_csv.sh" to make a csv file based on the results including the header.
-- ##########################################################
sh lib_and_extras/preparing_csv.sh '$outputFolder'
