#!/bin/bash
filename=$1
if [[ $filename =~ pcap ]] #Differenciating pcap and pcapng. NOTE: some .pcap are actually pcapng
then
  capinfos $filename > tmp
  pcaptype=`cat tmp | grep "File type"| awk -F - '{print $2}'`
  if [ $pcaptype = "pcap" ]
  then
    echo $pcaptype
  else
  	echo "pcapng"
  fi
elif [[ $filename =~ nfcapd ]]
	then
	echo "nfcapd"
else
	echo "filetype not recognized"
fi