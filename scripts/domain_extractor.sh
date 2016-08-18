#!/bin/bash
OUT=$2
find $1 -name "*.pcap.gz" | \
    xargs -n 1 tshark -T fields -e ip.src -e dns.qry.name -Y "dns.flags.response eq 0" -r | \
    #awk '$2>0 { if (system("grep " $2 " ${OUT}") == 1) print $2 }'
    awk '$2>0 { print $2 }' | xargs -n 1 ./appender.sh ${OUT}
