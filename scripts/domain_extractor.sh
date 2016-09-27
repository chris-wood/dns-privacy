#!/bin/bash
OUT=$2
find $1 -name "*.pcap" | \
    xargs -n 1 tshark -T fields -e ip.src -e dns.qry.name -Y "dns.flags.response eq 0" -r | \
    awk '$2>0 { print $2 }' | xargs -n 1 python domain_processor.py ${OUT}
