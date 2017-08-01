#!/bin/sh

repeat=10
#for count in $(seq 1 $repeat) ;do
#       echo $count
#done

for count in $(seq 1 $repeat) ;do
        ryu-manager a.py &
        tcpdump -i c1-p1 tcp -w "mypcap_new_$count.pcap" &
        sleep 60
        pgrep "ryu-manager" | xargs kill
        pgrep "tcpdump" | xargs kill
        sleep 60
done
